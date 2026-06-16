Stream has EXACTLY TWO query DSLs. Both are dialects of StreamQL with the same operator/date grammar but different searchable field sets:

- **SCQL** (Stream Certificates Query Language) — the `query` string for `search_certificates`, `aggregate_certificates`, `search_ssh_certificates`, and `aggregate_ssh_certificates`.
- **SEQL** (Stream Events Query Language) — the `query` string for `search_events`.

There is no other query language in Stream. Parse errors on either DSL come back as HTTP 400 `STREAMQL-001` with a `detail` describing the bad token/position.

## SCQL (certificates)

Used by `search_certificates` + `aggregate_certificates` (X509) and `search_ssh_certificates` + `aggregate_ssh_certificates` (SSH). Same grammar, slightly different field sets per cert type.

### Searchable fields — X509 (`search_certificates` / `aggregate_certificates`)

- **String fields:** `ca`, `dn`, `issuer`, `serial`, `publickeythumbprint`, `template`.
- **Date fields:** `valid.from` (→ notBefore), `valid.until` (→ notAfter), `revocation.date`.
- **Id field:** `id` (must be a 24-hex Mongo ObjectId).
- **Status pseudo-field:** `status` ∈ `valid` | `expired` | `revoked`.
  - `expired` = notAfter < now; `revoked` = notAfter ≥ now AND revoked; `valid` = notAfter ≥ now AND not revoked.

Note: `revoked` is NOT a registered SCQL field — use `status` for validity/revocation predicates.

### Searchable fields — SSH (`search_ssh_certificates` / `aggregate_ssh_certificates`)

- **String fields:** `ca`, `serial`, `publickeythumbprint`, `template`, `type` (`USER`/`HOST`), `principals`, `keyid`.
- **Date fields:** `valid.from`, `valid.until`, `revocation.date`.
- **Id field:** `id`.
- **Status pseudo-field:** `status` ∈ `valid` | `expired` | `revoked`.

### Operators (both X509 and SSH)

| Operator                                    | Applies to       | Meaning                                                                                                      |
| ------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------ |
| `equals` / `not equals`                     | id, string, date | Exact match. For dates, bucketed equality at the literal's precision (`equals 2025` matches the whole year). |
| `matches` / `not matches`                   | string           | Case-insensitive regex (value used raw, `i` flag).                                                           |
| `contains` / `not contains`                 | string           | Case-insensitive substring (value regex-escaped).                                                            |
| `in [a,b,...]` / `not in [...]`             | id, string       | `$in` / `$nin` over a literal array.                                                                         |
| `within [a,b,...]` / `not within [...]`     | string           | `$in` / `$nin` of case-insensitive escaped regexes.                                                          |
| `before <date>` / `not before`              | date             | `< date` / `>=`.                                                                                             |
| `after <date>` / `not after`                | date             | `>= date` / `<`.                                                                                             |
| `exists` / `not exists`                     | id, string       | Field present / absent.                                                                                      |
| `status is <v>` / `status is not <v>`       | status           | v ∈ valid/expired/revoked.                                                                                   |
| `status in [v,...]` / `status not in [...]` | status           | Set of statuses.                                                                                             |
| `and`, `or`, `( ... )`                      | —                | `and` binds tighter than `or`. Nesting capped by config.                                                     |

### Date literals

`now`, `today`, `YYYY`, `YYYY-MM`, `YYYY-MM-DD`, `YYYY-MM-DDTHH`, `YYYY-MM-DDTHH:mm`, `YYYY-MM-DDTHH:mm:ss` (optional trailing `Z`), and relative offsets `[-]<n>(days|day|d|hours|hour|h|minutes|minute|m|seconds|second|s)` — no sign = future, `-` = past (e.g. `-7days`, `30 days`).

### SCQL example queries

```
status is valid
status in [valid,expired]
template equals ServerCert and status is not revoked
valid.until before 30 days
serial equals 571868a4fa7dcdd5493399cf89b89001
type equals USER and status is valid          # SSH only
```

### Key SCQL rules

- **An empty `query` string `""` is REJECTED** → `400 STREAMQL-001 "Invalid condition: ''"`. This is true for both search and aggregate. To match everything, send a real catch-all predicate: **`id exists`** (do NOT send an empty string). For SSH search/aggregate you may also simply omit `query` entirely to match all.
- **`serial` is lowercase hex** in X509 (the BigInteger serial); match it as lowercase hex. SSH serial is a decimal/string value.
- **Omit `fields` to get the full result object.** If you pass `fields`, you get exactly that projection — the server internally forces `ca/certificate/notAfter(validBefore)/revoked/template` for permission math, then nulls out any of those you did not request. Invalid field → `400 CERTIFICATE-002` (X509) / `400 SSH-CERT-002` (SSH) listing the usable fields.
- X509 valid `fields` / sort elements: `id`, `ca`, `template`, `certificate`, `dn`, `serial`, `issuer`, `notBefore`, `notAfter`, `publicKeyThumbprint`, `revoked`, `revocationDate`, `revocationReason`, `permissions`.
- SSH valid `fields` / sort elements: `ca`, `certificate`, `id`, `keyId`, `permissions`, `publicKeyThumbprint`, `revocationDate`, `revoked`, `serial`, `template`, `type`, `validAfter`, `validBefore`.
- Aggregate uses `groupBy` (not `fields`). X509 groupBy: `expired`, `issuer`, `template`, `notAfter.{day,month,year}`, `notBefore.{day,month,year}`, `revocationDate.{day,month,year}`, `revocationReason`, `revoked`, `status`. SSH groupBy: `expired`, `template`, `type`, `validAfter.{day,month,year}`, `validBefore.{day,month,year}`, `revocationDate.{day,month,year}`, `revoked`, `status`. Invalid element → `400 STREAMQL-001` / `400 SSH-CERT-003`.

Aggregate example:

```json
{ "query": "id exists", "groupBy": ["status"], "withCount": true }
```

→ `{ "items": [ {"_id":{"status":"valid"},"count":3818}, {"_id":{"status":"expired"},"count":1881}, {"_id":{"status":"revoked"},"count":552} ], "count": 6251 }`

## SEQL (events)

Used by `search_events` only. Call `get_event_dictionary` first to learn the valid `code`, `module`, `status`, and `detail.<key>` literals for the running instance (it returns version-specific vocabulary, including deprecated values still on historical events).

### Searchable fields

- `id` — the event `_id` (24-hex ObjectId). Operators: `equals`, `in`.
- `code`, `node`, `module`, `status` — string fields. Operators: `equals`, `matches`, `contains`, `in`. Values are NOT enum-validated at parse time; an invalid `code`/`module`/`status` simply matches nothing. Use `get_event_dictionary` for the real literals (e.g. modules `service`, `x509.ca`, `x509.lifecycle`, `security`; codes `SERVICE-START`, `LIFECYCLE-ENROLL`, `SEC-AUTHENTICATION`; statuses `success`/`failure`/`warning`).
- `timestamp` — the only date field. Operators: `equals`, `before`, `after` (and `not` forms). Prefer `before` / `not before` for upper bounds (`not after` has a known translation bug).
- `detail.<key>` — event detail fields. Operators: `equals`, `matches`, `contains`, `in`, `within`, `exists`. `<key>` MUST be one of the dictionary `details` values (e.g. `detail.actorId`, `detail.ip`, `detail.message`, `detail.certificateSerial`) else parse error. `within` and `exists` apply to `detail.*` only.

### Date literals

Same as SCQL: `now`, `today`, the `YYYY[-MM[-DD[THH[:mm[:ss]]]]][Z]` precisions, and relative offsets like `-7days` / `30m`.

### Key SEQL rule

**For events, OMIT `query` (or send `null`) to match all** — an absent/null `query` compiles to an empty filter. Unlike SCQL, you do not need an `id exists` catch-all here. (Empty-string `""` is not a meaningful query; just leave the field out.)

### SEQL example queries

```
code equals SERVICE-START
module equals service and status equals success
status in [failure, warning]
detail.actorId equals administrator
detail.ip exists
timestamp after 2025-01-01 and timestamp before 2025-06-01
code matches ^SEC- and status not equals success
(module equals x509.ca or module equals x509.crl) and timestamp after 2025-04-01
```

Multi-word or special-char literal values must be quoted; single bare tokens (enum codes, hostnames) work unquoted as shown.

## Sorting & pagination

All four certificate search/aggregate tools and `search_events` share the same envelope controls. (Aggregate uses `sortOrder`/`limit`/`having` instead of `sortedBy`/paging — see the per-domain contracts.)

### sortedBy (search tools)

`sortedBy` is an array of `{ "element": <field>, "order": <SortOrder> }`.

- **`order` is case-sensitive**, one of: `Asc`, `Desc`, `KeyAsc`, `KeyDesc`. Only `Asc` and `KeyAsc` sort ascending (+1); `Desc` and `KeyDesc` sort descending (-1).
- `element` must be a valid sortable field for that tool:
  - **`search_events`:** exactly `code`, `id`, `module`, `node`, `removeAt`, `status`, `timestamp` (note `id`, NOT `_id`; `details` and `seal` are NOT sortable).
  - **`search_certificates`:** any X509 valid field (`id`, `ca`, `template`, `dn`, `serial`, `issuer`, `notBefore`, `notAfter`, `publicKeyThumbprint`, `revoked`, `revocationDate`, …).
  - **`search_ssh_certificates`:** any SSH valid field (`ca`, `serial`, `template`, `type`, `validAfter`, `validBefore`, …).
- Duplicate elements → `400` "Duplicated sort field(s)". Invalid element → `400` "Invalid sort field(s)".
- Default when omitted: DB natural order (effectively `_id` ascending).

### Pagination

| Field       | Type | Default                               | Notes                                                                                 |
| ----------- | ---- | ------------------------------------- | ------------------------------------------------------------------------------------- |
| `pageIndex` | int  | `1`                                   | **1-based.** Any value `< 1` is coerced to `1`. Mongo skip = (pageIndex-1)\*pageSize. |
| `pageSize`  | int  | `50` (events) / domain config (certs) | Page size. Certs cap at a configured max if exceeded; events uncapped by default.     |
| `withCount` | bool | `false`                               | When `true`, the response includes total `count`. When false, `count` is omitted.     |

Every search response also returns `hasMore` (computed by over-fetching one extra row) so you can page until `hasMore` is false.

### Example: paged, sorted, counted

```json
// search_events: oldest first, page 1 of 2, with total count
{
  "sortedBy": [{ "element": "timestamp", "order": "Asc" }],
  "pageIndex": 1,
  "pageSize": 2,
  "withCount": true
}
```

→ `{ "results": [ … ], "pageIndex": 1, "pageSize": 2, "count": 1780381, "hasMore": true }`

```json
// search_certificates: expiring soon, newest expiry first, projected fields
{
  "query": "valid.until before 30 days and status is valid",
  "fields": ["id", "dn", "ca", "template", "notAfter"],
  "sortedBy": [{ "element": "notAfter", "order": "Desc" }],
  "pageIndex": 1,
  "pageSize": 50,
  "withCount": true
}
```

> Reminder: search tools never return 204 for an empty result — they return `200` with `"results": []`. (List-style endpoints elsewhere in Stream do return 204 when empty, but the search/aggregate query tools do not.)
