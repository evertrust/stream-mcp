System administration for Evertrust Stream: server-wide configuration, HTTP proxies, signing queues, license/entitlement inspection, validation dictionaries, full-config export, and the append-only JWS-sealed audit-event log. Read this before calling any `*_system_configuration`, `*_proxy`, `*_queue`, `get_license_*`, `get_*` dictionary, `export_configuration`, or event tool.

All admin objects follow Stream's universal rules: the name/type is the **immutable primary key**, updates are **full-replace** (the MCP does GET-strip-merge-PUT for you), secrets are **write-only / redacted on read**, and list endpoints that find nothing return an **empty list** (Stream replies 204; the tools normalize to `[]`). Stream auth is **local account** (`X-API-ID` / `X-API-KEY` / `X-API-IDPROV`) or **X509/mTLS** — there is no OIDC for the MCP's own auth.

## System configuration

A small set of polymorphic, server-wide config entries keyed by `type`. Tools:

- `list_system_configuration` — array of all configured entries (one per type).
- `get_system_configuration` — one entry by `type`.
- `upsert_system_configuration` — create-or-replace, **keyed by `type`** (NOT by id/name).

The audited/live `type` values are exactly **`license`** and **`internal_monitor`**. (Other categories like SMTP/email or LDAP are managed as their own dedicated objects, not as system-configuration entries on this instance — do not pass a `type` the dictionary doesn't list; unknown type → 400.)

Per-type body shape:

- `license` (LicenseConfiguration): optional `triggers.onLicenseExpiration` = array of pre-existing **trigger names** fired on license expiry. Example: `{ "type": "license", "triggers": { "onLicenseExpiration": ["notify-admins"] } }`
- `internal_monitor` (InternalMonitorConfiguration): **required** `cron` = a Quartz cron string (e.g. `"0 0 0 ? * * *"`), parsed by `org.quartz.CronExpression`; invalid → validation error. The server may round-trip extra whitespace on read (e.g. `"0 * * ? * * "`).

`upsert_system_configuration` is the only write path (no POST/DELETE). It looks up the existing entry of the same `type`: found → 200 full-replace reusing the prior id; not found → 201 create. `id` is server-assigned and ignored on writes. Requires `SystemConfiguration:MANAGE`.

## HTTP proxies

Named outbound-HTTP proxies referenced by keystores, X509 CAs, and triggers. Full CRUD: `list_proxies`, `get_proxy`, `create_proxy`, `update_proxy`, `delete_proxy`.

`HttpProxy` body fields:

- `name` (required) — immutable primary key. Ask the user; never infer.
- `host` (required) — an RFC952 hostname (must contain a dot, e.g. `proxy.corp.example.com`), an IPv4 address/range/CIDR, or an IPv6 address/CIDR. Bad value → `PROXY-002`.
- `port` (required) — 1..65535 inclusive.

Example: `create_proxy { "name": "corp-proxy", "host": "proxy.corp.example.com", "port": 8080 }`

`update_proxy` is a full-replace by `name` (the MCP merges from the current record). `delete_proxy` fails with `PROXY-005` if the proxy is still referenced by any keystore, X509 CA, or trigger — remove those references first. Duplicate name on create → `PROXY-004`. (Username/password/noProxy fields are not part of the audited 2.1 `HttpProxy` shape — do not send them.)

## Queues

Signing/work queues that throttle and serialize background work such as CA issuance. Full CRUD: `list_queues`, `get_queue`, `create_queue`, `update_queue`, `delete_queue`.

`Queue` body fields:

- `name` (required) — immutable primary key.
- `size` (required) — integer > 0.
- `cluster_wide` (required) — boolean (wire field `clusterWide`).
- `description` (optional) — free text.
- `throttle_duration` (optional) — a FiniteDuration string matching `^([0-9]+) *(ms|...|days)$`, e.g. `"1 second"`, `"500 ms"`, `"5 minutes"`. Must be > 0.
- `throttle_parallelism` (optional) — integer > 0.

**Quirk:** if you set `throttle_duration` you MUST also set `throttle_parallelism`, else Stream rejects with "Throttle duration must be defined with throttle parallelism" (the MCP also validates this client-side).

Example: `create_queue { "name": "issuance", "size": 10, "throttle_duration": "1 second", "throttle_parallelism": 5, "cluster_wide": true }`

`update_queue` is full-replace by `name`; omitted optional fields reset to the current record's values via GET-strip-merge-PUT, so use `clear_fields` (e.g. `["description","throttleDuration","throttleParallelism"]`) to explicitly null optional fields. Duplicate name on create → `QUEUE-004`. `delete_queue` fails with `QUEUE-005` if any managed X509 CA still points at the queue — repoint those CAs first. There is no auto-created `default` queue; `get_queue default` → 404 unless you created one.

## License and entitlements

- `get_license_info` — full `LicenseInfo`: `isValid`, `expiration` (ISO instant, omitted if perpetual), `version`, `buildTime`, `modules` (entitled module entryNames, sorted), `libraries` (`{name, version}`), `releaseChannel`.
- `get_license_modules` — just the entitled module entryNames. **No auth required** (plain action); returns an empty list if nothing entitled.

Module entryNames map to product entitlements:

- `stream-ca` → certificate authority / issuance (X509 CA tools, EKUs, templates).
- `stream-va` → validation authority (OCSP signers).
- `stream-tsa` → timestamping authority/signers.
- `stream-ssh` → SSH certificate authority.

Use these to gate behavior: a tool that needs TSA will fail if `stream-tsa` isn't in `modules`. (Note the two endpoints order modules differently — `get_license_info.modules` is alphabetical; `get_license_modules` is declaration order CA/VA/TSA/SSH. Treat both as sets.)

## Dictionaries — valid-input vocabularies

Read-only, always non-empty lists that drive what you may submit elsewhere (CA/template/CSR inputs). Fetch them live rather than hardcoding — the sets are license/version-dependent.

- `get_key_types` — supported asymmetric algorithms as `{ name, pqc, type }`. `type` groups: `RSA`, `EC`, `ED`, `ML-DSA`, `SLH-DSA`. `name` examples: `rsa-2048`, `ec-secp256r1`, `ed-25519`, `mldsa-65`, `slhdsa-sha2-128s`. `pqc` is `true` only for ML-DSA / SLH-DSA.
- `get_dn_elements` — valid DN component names for distinguished names, e.g. `CN`, `O`, `OU`, `C`, `ST`, `L`, `E`, `SERIALNUMBER`, `DC`, `ORGANIZATIONIDENTIFIER`.
- `get_san_types` — valid Subject Alternative Name types: `RFC822NAME`, `DNSNAME`, `URI`, `IPADDRESS`, `OTHERNAME_UPN`, `OTHERNAME_GUID`, `REGISTERED_ID`.

When building a certificate request or template and unsure whether a key algorithm, DN element, or SAN type is accepted, call the matching dictionary tool first — these lists are the source of truth for what Stream will accept, and they vary by license and version. `get_key_types` is the best signal for post-quantum support: filter on `pqc: true` to see which ML-DSA / SLH-DSA variants this instance offers.

## Config export

- `export_configuration` — returns the **AsciiDoc** "Stream Configuration Cookbook" as plain text (NOT JSON): a human-readable dump of every auditable entity (CAs, timestamping, keystores, queues, proxies, system config, security, ...). Optional `withTrustChains` (boolean) prepends Graphviz/DOT trust-chain diagrams.

This document is **large** (hundreds of KB; trust-chains makes it larger) and the body is gated by what the caller can audit. Use it for a full-config snapshot/diff or to answer "what is configured" — not for programmatic field lookups (use the typed list/get tools for those).

## Audit events

Stream keeps an **append-only, immutable** audit log. Events are JWS-sealed (HS512) for tamper-evidence when chainsign is enabled — there are **no create/update/delete** event tools. Query with **SEQL** (Stream Events Query Language).

- `search_events` — paginated search via a SEQL `query` string. All request fields optional: `query` (SEQL; absent ⇒ match all), `sortedBy` (`{element, order}`), `pageIndex` (1-based, <1 coerced to 1), `pageSize` (default 50), `withCount` (bool; populates `count`). Always returns 200 with `{ results, pageIndex, pageSize, count?, hasMore }` — empty matches give `{ "results": [], ... }`, never 204.
- `get_event` — one event by 24-hex ObjectId. Non-ObjectId → binder 400; unknown id → `EVT-003`.
- `get_event_dictionary` — the authoritative runtime vocabulary `{ modules, codes, details }`. **Call this to discover valid `code` / `module` / `status` / `detail.<key>` literals before writing SEQL.**
- `run_event_integrity_check` — fire-and-forget chain-verification of the sealed log; optional `startFrom` ObjectId. Returns immediately (no inline report); requires `chainsign=true` + `seal.secret`. Poll afterwards.
- `list_event_integrity_reports` — all `EventIntegrityReport`s, each re-verified on read (`status` may be server-overridden: `verified`, `running`, `eventIntegrityFailure`, `reportIntegrityFailure`, `unexpectedFailure`).

`EventSearchResult` fields: `id`, `code`, `module`, `node`, `timestamp`, `status` (`success`/`failure`/`warning`), optional `details[]` (`{key,value}`), optional `seal` (read-only JWS). `seal` and `details` are never sortable.

### SEQL essentials

SEQL is one of Stream's exactly two query DSLs — it powers `search_events` only. The other DSL is **SCQL** (for `search_certificates` / `search_ssh_certificates`). They are not interchangeable: an SCQL field in a SEQL query (or vice versa) is a parse error. There is no other query language in Stream.

Combine conditions with `and`/`or` (`and` binds tighter), group with `( )`, negate per-condition with `not` placed before the operator.

Searchable fields and operators:

- `id` — `equals`, `in` (values must be ObjectId hex).
- `code`, `node`, `module`, `status` — `equals`, `matches` (regex), `contains` (literal substring), `in [..]`. Not validated at parse time: an invalid enum value just matches nothing — confirm via `get_event_dictionary`.
- `timestamp` — `equals`, `before`, `after`. Dates: `now`, `today`, `YYYY[-MM[-DD[THH[:mm[:ss]]]]]` (UTC), or relative offsets like `-7days`, `30m`. (Avoid `not after` — use `before` for upper bounds.)
- `detail.<key>` — `equals`, `matches`, `contains`, `in`, `within`, `exists`. `<key>` MUST be in the dictionary `details` list or it's a parse error.

`sortedBy.element` must be one of `code, id, module, node, removeAt, status, timestamp` (uses `id`, not `_id`); duplicates rejected. `order` is case-sensitive: `Asc`/`KeyAsc` (asc), `Desc`/`KeyDesc` (desc).

Example SEQL:

```
code equals SERVICE-START
module equals security and status equals failure
status in [failure, warning]
detail.actorId equals administrator
detail.ip exists
code matches ^SEC- and status not equals success
timestamp after 2025-01-01 and timestamp before 2025-06-01
(module equals x509.ca or module equals x509.crl) and timestamp after -7days
```

### Event error codes

`EVT-001` unexpected (500), `EVT-002` invalid search query / bad sort (400), `EVT-003` event not found (404), `STREAMQL-001` SEQL parse error (400), `EVT-INTEGRITY-002` chainsign/seal.secret not configured (400), `SEC-PERM-001` permission denied (403; integrity-list returns 204 instead).
