The OpenSSH module manages SSH certificate authorities, certificate templates, signed SSH certificates, their enrollment/revocation lifecycle, and KRLs (Key Revocation Lists). It requires the SSH license module to be enabled; otherwise every call is rejected at the license layer.

Auth is local account (`X-API-ID`/`X-API-KEY`/`X-API-IDPROV`) or X509/mTLS — there is no OIDC for the MCP's own auth.

Two recurring conventions:

- Object `name` is the immutable primary key. At the API, updates are full-replace via PUT on the collection root (the body's `name` selects the object; the server forces `id = previous.id` and ignores client `id`). The MCP `update_*` tools merge for you: pass only the fields you change; omitted fields keep their current values (use `clear_fields` to null one).
- List endpoints return HTTP 204 (no body) when empty or when you lack audit permission — treat 204 as an empty list, not an error.

The SSH search/aggregate DSL is **SCQL** (SSH dialect). This is the only query language for SSH certificates. There is no other SSH query language.

## SSH CAs

Tools: `list_ssh_cas`, `get_ssh_ca`, `create_ssh_ca`, `update_ssh_ca`, `delete_ssh_ca`.

An SSH CA wraps an existing keystore private key and signs SSH certificates. Key fields:

| Field                 | Req                    | Notes                                                                                                                                                         |
| --------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                | yes                    | Immutable primary key.                                                                                                                                        |
| `privateKey`          | yes                    | `{ keystore, name, hashAlgorithm?, usePSS? }`. References an existing keystore + key alias. Key algorithm must be RSA, EC, or Ed25519.                        |
| `publicKey`           | no — **omit on write** | Server-derived from the private key. A CA is "ready" iff `publicKey` is present. Any client value is ignored/overridden.                                      |
| `enroll`              | yes                    | If false, enrollment on this CA is rejected with `LIFECYCLE-SSH-002`.                                                                                         |
| `enforceKeyUnicity`   | yes                    | If true, enroll fails when the public-key thumbprint already exists on this CA.                                                                               |
| `krlPolicy`           | yes                    | `{ validity, hardGeneration?, lazyGeneration? }`. `validity` (FiniteDuration, e.g. `"14 days"`) is required; the two cron fields are optional Quartz strings. |
| `queue`               | no                     | Optional queue name; must reference an existing queue.                                                                                                        |
| `triggers`            | no                     | KRL hooks: `onKRLGeneration`, `onKRLGenerationError`, `onKRLGenerationRecover`, `onKRLSync`, `onKRLSyncError` (each `string[]`).                              |
| `overridePermissions` | no                     | `{ type?, backdate?, lifetime? }` booleans. Gate whether enroll requests may override those fields.                                                           |

`privateKey.hashAlgorithm` is one of `SHA1`, `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512` (in practice `SHA256`/`SHA384`/`SHA512` for RSA/EC). Omit `hashAlgorithm` for Ed25519 (EdDSA uses no hash).

Minimal `create_ssh_ca` body:

```json
{
  "name": "my-ssh-ca",
  "privateKey": {
    "keystore": "SSH",
    "name": "my-ssh-ca",
    "hashAlgorithm": "SHA256"
  },
  "enroll": true,
  "enforceKeyUnicity": false,
  "krlPolicy": { "validity": "14 days" }
}
```

Errors: duplicate name → `SSH-CA-004`; bad keystore/key reference or parse error → `SSH-CA-002`; not found (get/update/delete) → `SSH-CA-003`; delete blocked because certificates reference the CA → `SSH-CA-005`.

### Generate KRL (`generate_krl`)

`generate_krl` triggers asynchronous KRL generation for a CA (optional `lazy=true` for lazy regeneration). It is **fire-and-forget**: it returns **204 No Content** and does NOT return the KRL artifact. Poll `get_krl` for the resulting status. If the CA has no public key (not ready) → `SSH-CA-006`; if the CA does not exist → `SSH-CA-003`.

## SSH templates

Tools: `list_ssh_templates`, `get_ssh_template`, `create_ssh_template`, `update_ssh_template`, `delete_ssh_template`.

A template constrains what an enroll request may produce. Fields:

| Field                | Req | Notes                                                                                                                       |
| -------------------- | --- | --------------------------------------------------------------------------------------------------------------------------- |
| `name`               | yes | Immutable primary key.                                                                                                      |
| `enabled`            | yes | Disabled templates are unusable for enroll and excluded from the requestable list.                                          |
| `lifetime`           | yes | FiniteDuration (e.g. `"30 days"`). Mandatory — missing → `SSH-TEMPLATE-002` ("lifetime is mandatory").                      |
| `type`               | no  | `USER` or `HOST` (uppercase, case-sensitive). If omitted, the enroll request must supply the type (subject to CA override). |
| `backdate`           | no  | FiniteDuration; backdates validity start.                                                                                   |
| `authorizedKeyTypes` | no  | Whitelist of allowed subject key types.                                                                                     |
| `principalPolicy`    | no  | `{ min?, max?, regex? }` constraints on enroll principals.                                                                  |

`type` is `CFSSHCertificateType`: exactly `USER` or `HOST`.

`authorizedKeyTypes` allowed values (server-validated whitelist): `ssh-rsa`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-ed25519`. Any other value → `SSH-TEMPLATE-002`.

`principalPolicy`: `min`/`max` are positive ints with `max >= min`; `regex` is a Java regex each principal must fully match. Invalid regex or `max < min` / `min <= 0` → `SSH-TEMPLATE-002`. Note the criticalOptions/extensions and validity behavior of a certificate are governed by the template's `lifetime`/`backdate` plus the CA — the template does not expose free-form criticalOptions/extensions fields.

`create_ssh_template` example:

```json
{
  "name": "user-tpl",
  "enabled": true,
  "type": "USER",
  "lifetime": "30 days",
  "backdate": "5 minutes",
  "authorizedKeyTypes": ["ssh-ed25519", "ecdsa-sha2-nistp256"],
  "principalPolicy": { "min": 1, "max": 5, "regex": "^[a-z][a-z0-9_-]{0,31}$" }
}
```

Errors: duplicate → `SSH-TEMPLATE-004`; not found/disabled → `SSH-TEMPLATE-003`. `delete_ssh_template` checks for a still-valid certificate using the template FIRST — if one exists → `SSH-TEMPLATE-005` (returned before the not-found check).

## SSH certificates

Query tools: `search_ssh_certificates`, `aggregate_ssh_certificates`, `get_ssh_certificate`.

Certificates are PEM/OpenSSH-out: the response `certificate` field is an OpenSSH cert pub string (`...-cert-v01@openssh.com AAAA...`). The full object is rich; there is no PEM-in editing of an existing certificate (you enroll new ones, you do not mutate them).

**`serial` is a STRING on the wire** even though stored as a Long — the writer overrides it to `serial.toString()`. Treat serial as a decimal string everywhere (search results, get, and revoke-by-serial input).

### search_ssh_certificates

Body: `{ query?, fields?, sortedBy?, pageIndex?, pageSize?, withCount? }`.

- `query`: SCQL expression; omit to match all. Empty string `""` → 400 `STREAMQL-001`.
- `fields`: projection, must be a subset of valid fields else 400 `SSH-CERT-002`.
- `pageIndex` defaults to 1 (values < 1 coerced to 1); `pageSize` defaults to 50.

Valid `fields` / `sortedBy[].element`: `ca`, `certificate`, `id`, `keyId`, `permissions`, `publicKeyThumbprint`, `revocationDate`, `revoked`, `serial`, `template`, `type`, `validAfter`, `validBefore`.

`sortedBy[].order` is `Asc` / `Desc` / `KeyAsc` / `KeyDesc` (case-sensitive).

SCQL grammar (SSH dialect, lowercase field tokens):

- String fields: `ca`, `serial`, `publickeythumbprint`, `template`, `type`, `principals`, `keyid` with `equals` / `not equals`, `matches`, `contains`, `in [..]`, `within [..]`, `exists`.
- Date fields: `valid.from`, `valid.until`, `revocation.date` with `equals <date>`, `before <date>`, `after <date>`, `within [..]`. Dates: `now`, `today`, or ISO `yyyy-MM-ddTHH:mm:ss[Z]`.
- Id: `id equals "..."`, `id in [...]`, `id exists`.
- Status: `status is [not] valid|revoked|expired`, `status in [valid,revoked,...]`.
- Combine with `and` / `or` / parentheses.

Examples:

```
type equals "USER"
status is valid and ca equals "sma-rsa"
```

> **Known data quirk (some instances):** `search_ssh_certificates` may return 500 `SSH-CERT-001` with `"readString can only be called when CurrentBSONType is STRING, not when CurrentBSONType is INT64"`. This is a server-side INT64/STRING deserialization bug for pre-existing certs, NOT a query error (a bad `query` still returns 400 `STREAMQL-001`, bad `fields` returns 400 `SSH-CERT-002` first). When you hit this, fall back to `aggregate_ssh_certificates`, which avoids the affected path.

### aggregate_ssh_certificates

Body: `{ query?, groupBy?, withCount?, sortOrder?, limit?, having? }`.

- `groupBy`: subset of the whitelist `expired`, `template`, `type`, `status`, `revoked`, `revocationReason`, `validAfter.{day,month,year}`, `validBefore.{day,month,year}`, `revocationDate.{day,month,year}`, `profile` (last two/`profile`/`revocationReason` are X509-legacy and not populated on SSH certs). Invalid element → 400 `SSH-CERT-003`.
- `sortOrder`: `Asc` / `Desc` / `KeyAsc` / `KeyDesc`.
- `having`: `{ operator, value }` where operator is lowercase `gt` / `gte` / `lt` / `lte` / `eq` / `ne`.

Response: `{ items: [ { "_id": { "<groupKey>": <value> }, "count": <int> }, ... ], count? }`. Null/missing group values bucket as `"#empty"`.

Examples:

```json
{ "groupBy": ["type"], "withCount": true }
{ "query": "status is expired", "groupBy": ["template"], "sortOrder": "Desc", "limit": 5, "having": { "operator": "gte", "value": 1 } }
```

### get_ssh_certificate

`get_ssh_certificate` takes the Mongo ObjectId `id` (24-hex), NOT the serial. Returns `{ certificate: {...}, permissions: { revoke: <bool> } }`. Not found / no access → 404 `SSH-CERT-004` (returns not-found rather than 403 for privacy). `permissions.revoke` is true only when the cert is not revoked, not expired, and the principal may revoke it.

## Lifecycle

Tools: `enroll_ssh_certificate`, `revoke_ssh_certificate`, `list_requestable_ssh_templates`.

### enroll_ssh_certificate

Body: `{ ca, publicKey, template, principals }` (all required).

- `publicKey`: the OpenSSH subject public key to sign.
- `template`: `{ name, type?, lifetime?, backdate? }` — `name` is a required, **enabled** template. The optional overrides are allowed only if the CA's `overridePermissions` grants them.
- `principals`: `string[]` (user names for `USER`, host names for `HOST`); may be empty only if the template policy allows.

Returns **201** with the full signed `SSHCertificate` (including the OpenSSH `certificate` string and `serial` as a string).

```json
{
  "ca": "sma-rsa",
  "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
  "template": { "name": "user-tpl" },
  "principals": ["alice"]
}
```

Validation order (errors): CA missing → `SSH-CA-003`; CA not ready → `LIFECYCLE-SSH-003`; CA `enroll=false` → `LIFECYCLE-SSH-002`; template missing/disabled → `SSH-TEMPLATE-003`; principal/key-type/policy violation → `LIFECYCLE-SSH-004`; insufficient permission → `SEC-PERM-001`.

### revoke_ssh_certificate

Identify the cert one of two mutually-exclusive ways:

- By certificate: `{ "certificate": "<OpenSSH cert pub>" }` (preferred; if present, `serial`/`ca` are ignored).
- By serial + CA: `{ "serial": "12345", "ca": "sma-rsa" }` — both required together. Serial is a decimal string. Providing only one of the pair → parse error. None present → parse error. All parse errors → 400 `LIFECYCLE-SSH-006`.

Returns **200** with the (now-revoked) certificate. Revocation is idempotent: already-revoked or expired certs return 200 successfully. Not found → 404 `LIFECYCLE-SSH-007`; no permission → `SEC-PERM-001`.

### list_requestable_ssh_templates

Lists, per ready CA, the templates the caller may use. Optional `permission` query param: `enroll` / `revoke` / `search` (case-sensitive lowercase, **default `search`**). For `enroll` it also requires the CA's `enroll=true`. Bad value → 400 Play enum-bind error. Response: `[ { "ca": "<name>", "templates": ["<name>", ...] }, ... ]`. Empty → 204.

## KRL

Tools: `list_krls`, `get_krl`.

These expose KRL **status/metadata** (`KRLInfo`), not the KRL artifact itself. The binary KRL is produced asynchronously by `generate_krl` and stored server-side.

`KRLInfo` fields: `id`, `ca` (CA name), `number` (KRL version), `thisUpdate` (Instant), `nextRefresh` (Instant), `error` (present as a stack-trace string only when the last generation failed).

`list_krls` returns an array (empty → 204). `get_krl` takes the **CA name** as path param and returns one `KRLInfo`.

> Quirk: `get_krl` returns **404 `SSH-CA-003`** (the CA-not-found code, not a KRL-specific code) when no KRL info exists yet for that CA — including a CA that exists but has never generated a KRL. After calling `generate_krl`, expect 404 until generation completes; poll `get_krl` to detect when `thisUpdate`/`number` appear.
