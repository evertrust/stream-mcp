## Certificate templates (X509 profiles + SSH templates)

Templates define the _issuance policy_ for certificates: which subject/SAN
values are allowed, which extensions are added, and how long the cert lives. A
template is NOT a CA. It carries **no `ca`, no `keyType`, no
`signatureHashAlgorithm`, no `validity`** field — those concepts live on the CA
and lifecycle/enrollment entities, not here. Validity on a template is
`lifetime` (a FiniteDuration), never `validity`.

Two independent template kinds, each a standard name-keyed CRUD entity:

- **X509 certificate templates** — `/api/v1/templates`
- **SSH certificate templates** — `/api/v1/ssh/templates`

Shared rules for both:

- `name` is the immutable primary key (X509 regex `^[0-9a-zA-Z-_\.]+$`).
- Update is **full-replace keyed by the body `name`** (no `:name` on PUT). The
  MCP update tools do GET -> strip `id` -> merge your fields -> PUT for you.
- `id` is server-managed: generated on create, preserved on update. Never send it.
- List returns `[]` when empty or forbidden (server 204 -> empty array).
- DELETE is blocked while any **valid** (non-expired, non-revoked) certificate
  was issued under the template; on success it cascades cleanup into Role /
  PrincipalInfo (X509) or account+role permissions (SSH).
- No secret/write-only fields — every field round-trips.
- All endpoints require the **CA module license**.

## X509 templates — tools

| Tool              | Action                                            |
| ----------------- | ------------------------------------------------- |
| `list_templates`  | List all (sorted by name)                         |
| `get_template`    | Get one by name (disabled templates ARE returned) |
| `create_template` | Create (fails if name exists)                     |
| `update_template` | Full-replace by body name                         |
| `delete_template` | Delete by name                                    |

## X509 template body

Mandatory on create: `name`, `lifetime`, `enabled`, and the four `*FromCA`
inheritance booleans (`crldpsFromCA`, `aiaFromCA`, `policyFromCA`,
`qcStatementFromCA`). At least one Key Usage value must be defined.

### Inherit from the CA — keep templates general (DEFAULT; do this)

A template has **no `ca` field**: the same template is reused across CAs. Lean
into that. The four `*FromCA` booleans make the issued certificate pull these
extensions from **whichever CA issues it**, at enrollment time, instead of
hardcoding them on the template:

| `*FromCA = true`    | the issued cert's … is taken from …                                                                                     |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `crldpsFromCA`      | CRL Distribution Points ← the CA's `crldps`                                                                             |
| `aiaFromCA`         | Authority Information Access — **CA-issuers URL _and_ the OCSP responder URL** ← the CA's `aia` (`{certificate, ocsp}`) |
| `policyFromCA`      | Certificate Policies ← the CA's `policy`                                                                                |
| `qcStatementFromCA` | eIDAS QC statement ← the CA's `qcStatement`                                                                             |

**Prefer `*FromCA: true` and configure the CRL DP / AIA / OCSP responder once on
the CA** (`create_ca` / `update_ca`: `crldps`, `aia.ocsp`, `ocspSigner`). Then a
single broad template serves every CA — you never hardcode per-CA URLs and you
do not create a template per CA. This is the intended PKI wiring: revocation and
issuer-info pointers live on the CA; templates only describe issuance _policy_.

So when building a trust chain or an OCSP/CRL setup, the answer is **one general
template with `crldpsFromCA: true` and `aiaFromCA: true`**, not several templates
that each restate the CRL DP / AIA / OCSP URLs. The OCSP responder URL is part of
AIA — `aiaFromCA: true` inherits it automatically; there is no separate "OCSP
template".

Only set `*FromCA: false` together with an explicit `crldps` / `aia` (or
`policy` / `qcStatement`) when you deliberately need to **override** the CA's
value for a specific issuance policy. (At enrollment a request may also override
these per-cert, but only if the CA's `overridePermissions` allow it.)

**Minimalism rule for ALL templates (X509 + SSH):** make each template as general
as possible and inherit/derive as much as you can from the CA, so you manage the
fewest templates. Create a new template only for a genuine _policy_ difference
(key usage, EKU, lifetime, subject/SAN constraints) — never just to vary the CRL
DP, AIA, or OCSP wiring, which belongs on the CA.

Key fields (wire names):

| Field                    | Type                       | Notes                                                                                                       |
| ------------------------ | -------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `name`                   | string                     | Immutable key.                                                                                              |
| `lifetime`               | FiniteDuration             | **Mandatory.** Cert validity. Accepts `"365d"` or `"365 days"`; reads back as `"365 days"`. NOT `validity`. |
| `backdate`               | FiniteDuration             | Optional notBefore backdating (e.g. `"5 minutes"`, `"0 days"`).                                             |
| `enabled`                | boolean                    | Disabled templates are not requestable.                                                                     |
| `ku`                     | KeyUsage object            | Key Usage (see below).                                                                                      |
| `eku`                    | ExtendedKeyUsage object    | Extended Key Usage (see below).                                                                             |
| `subject`                | DNElement[]                | DN/subject constraints. If present must be non-empty.                                                       |
| `sans`                   | SANElement[]               | SAN constraints.                                                                                            |
| `extensions`             | ExtensionElement[]         | Microsoft extensions (`ms_template`/`ms_template_v2`/`ms_sid`).                                             |
| `emptyExtensions`        | enum[]                     | Only `no_revocation_check`; no duplicates.                                                                  |
| `policy`                 | CertificatePolicy[]        | Certificate policies.                                                                                       |
| `pathLen`                | int                        | basicConstraints pathLenConstraint.                                                                         |
| `removeBasicConstraints` | boolean                    | Removes BasicConstraints. Cannot be `true` if `ku` contains `keyCertSign`.                                  |
| `qcStatement`            | QCStatement object         | eIDAS QC statement (see below).                                                                             |
| `privateKeyUsagePeriod`  | object                     | `{notBefore, notAfter}` ISO-8601 instants; notBefore < notAfter.                                            |
| `aia`                    | AuthorityInformationAccess | `{certificate:[urls], ocsp:[urls]}`.                                                                        |
| `crldps`                 | string[]                   | CRL distribution point URLs.                                                                                |
| `checkPoP`               | boolean                    | Check CSR proof-of-possession (default true).                                                               |
| `extraCsrExtensions`     | string[] (OIDs)            | CSR extensions to copy verbatim.                                                                            |

### keyUsage (`ku`)

`{ "critical": bool, "values": [ ... ] }` — all 9 values:
`digitalSignature`, `nonRepudiation`, `keyEncipherment`, `dataEncipherment`,
`keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`.
At least one KU value must exist across the template, or create/update fails.

### extendedKeyUsage (`eku`)

`{ "critical": bool, "values": [ { "name": str, "oid": str, "custom": bool } ] }`.
`oid` must be a valid OID. Built-in EKUs (e.g. `serverAuth 1.3.6.1.5.5.7.3.1`,
`clientAuth 1.3.6.1.5.5.7.3.2`, `OCSPSigning 1.3.6.1.5.5.7.3.9`,
`msSmartCardLogon 1.3.6.1.4.1.311.20.2.2`) need no setup. Any **custom** EKU
(not a built-in) must already exist as a Custom EKU object at
`/api/v1/extension/ekus`, or upsert fails with `CERTIFICATE-TEMPLATE-002`.

### subject DN constraints (`subject[]`)

`{ "type": <DnElement>, "mandatory": bool, "editable": bool, "value": str?, "regex": str?, "whitelist": [str]? }`.

- `mandatory` = the DN element must be present; `editable` = requester may
  supply/override it.
- If `!editable` you must supply a default `value`.
- `regex` and `whitelist` are mutually exclusive on the same element.
- `regex` must compile and start with `^` / end with `$`. If both `regex` and
  `value` are set, `value` must match. If `whitelist` and `value` are set,
  `value` must be in the (non-empty) whitelist.
- `value` may be templated, e.g. `"OrElse({{csr.subject.cn.1}},{{csr.san.dnsname.1}})"`.
- Same `type` may repeat (re-indexed as `ou.1`, `ou.2`, ...).

DnElement types: `CN`, `UID`, `SERIALNUMBER`, `SURNAME`, `GIVENNAME`, `T`,
`UNSTRUCTUREDADDRESS`, `UNSTRUCTUREDNAME`, `E`, `OU`, `ORGANIZATIONIDENTIFIER`,
`PSEUDONYM`, `UNIQUEIDENTIFIER`, `STREET`, `ST`, `L`, `O`, `C`, `DESCRIPTION`,
`DC`, `VID`, `PID`, `NODEID`, `FWSIGNINGID`, `ICACID`, `RCACID`, `FABRICID`,
`NOCCAT`.

### SAN constraints (`sans[]`)

`{ "type": <CFSanType>, "min": int?, "max": int?, "regex": str? }`.
No duplicate `type`; `min/max >= 0` and `max >= min`; `regex` must compile and
be anchored (`^...$`).

CFSanType values: `RFC822NAME`, `DNSNAME`, `URI`, `IPADDRESS`,
`OTHERNAME_UPN`, `OTHERNAME_GUID`, `REGISTERED_ID`.

### extensions (`extensions[]`)

`{ "type": <type>, "value": str?, "mandatory": bool, "editable": bool }`.
Types: `ms_template`, `ms_template_v2`, `ms_sid`. No duplicate `type`. `ms_sid`
must NOT carry a `value`.

### qcStatement (eIDAS)

`{ "eTSIQCCompliance": bool, "eTSIQCSSCD": bool, "eTSIRetentionPeriod": int (>=0),
"eTSIQCType": <type>, "eTSIPDS": {lang:url}?, "eTSITransactionLimit":
{valueLimit:int, valueLimitExp:int, currencyCode:str}?, "eTSILegislation": [str]? }`.
`eTSIQCType` ∈ `WEB`, `ESIGN`, `ESEAL`, `NONE` (read case-insensitive, written
uppercase). `currencyCode` must be exactly 3 uppercase chars.

### Minimal X509 create (general template, inherits from the CA)

Note the `*FromCA` booleans: CRL DP / AIA (incl. the OCSP responder URL) /
policies are inherited from the issuing CA, so this one template works for every
CA and carries no hardcoded URLs. Set `crldps` / `aia` explicitly only to
override — see "Inherit from the CA" above.

```json
{
  "name": "tls-server",
  "ku": { "critical": true, "values": ["digitalSignature", "keyEncipherment"] },
  "eku": {
    "critical": false,
    "values": [{ "name": "serverAuth", "oid": "1.3.6.1.5.5.7.3.1" }]
  },
  "crldpsFromCA": true,
  "aiaFromCA": true,
  "policyFromCA": true,
  "qcStatementFromCA": false,
  "lifetime": "365d",
  "enabled": true
}
```

## SSH templates — tools

| Tool                  | Action                                  |
| --------------------- | --------------------------------------- |
| `list_ssh_templates`  | List all                                |
| `get_ssh_template`    | Get one by name (disabled returned too) |
| `create_ssh_template` | Create (fails if name exists)           |
| `update_ssh_template` | Full-replace by body name               |
| `delete_ssh_template` | Delete by name                          |

## SSH template body

Mandatory on create: `name`, `enabled`, `lifetime`. The SSH template entity is
small — there is **no `criticalOptions` and no `validity` field on the
template** (per-issuance critical options and forced-command overrides live on
the enroll _request_ template, not on the template entity).

| Field                | Type             | Notes                                                                          |
| -------------------- | ---------------- | ------------------------------------------------------------------------------ |
| `name`               | string           | Immutable key.                                                                 |
| `enabled`            | boolean          | **Mandatory.** Disabled = not usable for enroll.                               |
| `lifetime`           | FiniteDuration   | **Mandatory.** Cert validity, e.g. `"30 days"`. NOT `validity`.                |
| `type`               | `USER` or `HOST` | Optional. If omitted, the enroll request supplies it (subject to CA override). |
| `backdate`           | FiniteDuration   | Optional backdate of validity start.                                           |
| `authorizedKeyTypes` | string[]         | Optional server-validated whitelist of SSH key types.                          |
| `principalPolicy`    | object           | Optional constraints on enroll principals.                                     |

`authorizedKeyTypes` allowed values: `ssh-rsa`, `ecdsa-sha2-nistp256`,
`ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`, `ssh-ed25519`. Any other value
fails with `SSH-TEMPLATE-002`.

`principalPolicy` = `{ "min": int?, "max": int?, "regex": str? }` (all optional):
`min > 0`, `max > 0` and `max >= min`, `regex` is a Java regex each principal
must fully match. Bad regex / min / max -> `SSH-TEMPLATE-002`. Serialized as
`{}` when present but all-empty.

### SSH create example

```json
{
  "name": "user-tpl",
  "enabled": true,
  "type": "USER",
  "lifetime": "30 days",
  "authorizedKeyTypes": ["ssh-ed25519", "ecdsa-sha2-nistp256"],
  "principalPolicy": { "min": 1, "max": 5, "regex": "^[a-z][a-z0-9_-]{0,31}$" }
}
```

## Quirks and error codes

- **`lifetime` is mandatory** on both kinds even though it is modeled as
  optional — omitting it throws `lifetime is mandatory` -> 400.
- **FiniteDuration asymmetry**: send `"365d"`, read back `"365 days"`.
- **Update is full-replace.** Any optional field omitted from the body is
  dropped on the stored document. The MCP update tools merge your fields over
  the current record before PUT; use `clear_fields: ["aia","subject"]` to null
  an optional field on purpose. Cannot target `id` or `name`.
- **`name` cannot be renamed** — PUT with a different name just targets a
  different (or nonexistent) record.

X509 error codes: `CERTIFICATE-TEMPLATE-002` (validation / bad JSON / missing
custom EKU), `-003` (not found), `-004` (name exists on create), `-005` (DELETE
blocked: valid cert references it). SSH mirrors these as `SSH-TEMPLATE-002..005`
(`-005` is checked BEFORE the not-found check on delete). `SEC-PERM-001` =
insufficient permissions (403, or 204 on list).
