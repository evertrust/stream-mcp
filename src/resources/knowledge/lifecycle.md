Certificate enrollment and revocation in Stream, for both X509 and SSH. Stream issues from a **CSR/public-key in** and returns a **rich certificate object out**. Issued certificates are persistent records: **they cannot be deleted — revocation is the only terminal action.** There is no centralized server-side key generation and no PKCS#12 return on these endpoints; the key pair is always generated client-side.

Tools covered: `enroll_certificate`, `revoke_certificate`, `list_requestable_templates` (X509); `enroll_ssh_certificate`, `revoke_ssh_certificate`, `list_requestable_ssh_templates` (SSH).

Before enrolling/revoking, use `list_requestable_templates` / `list_requestable_ssh_templates` to discover which `(ca, template)` pairs you may actually use for the chosen permission.

## X509 enroll — `enroll_certificate`

`POST /api/v1/lifecycle/enroll` → **201** with the full `X509Certificate` object (no permissions wrapper). CSR-based only.

Required inputs:

- `ca` — name of a **managed, enroll-enabled** X509 CA. Must be ready, not expired, not compromised/revoked, and you must hold enroll permission on `(ca, template)`. Unknown CA → `404 CA-003`; enroll disabled → `403 LIFECYCLE-002`; not ready → `403 LIFECYCLE-003`.
- `csr` — the PKCS#10 request as a **plain PEM string** (not an object). The CSR carries the public key — this is the only key source; there is NO `keyType`/centralized option here. Invalid PEM → `400`.
- `template_name` — the certificate template to issue against (must exist and be enabled).

Optional DN / SAN / extension overrides (all gated by the CA's `overridePermissions` — a disallowed override → `400 LIFECYCLE-004` "... cannot be overridden"):

- `dn` — RFC DN string. If both `dn` and `dn_elements` are given, **`dn` wins**.
- `dn_elements` — structured DN: array of `{ element, value }` where `element` is `<dnType>.<index>` **lowercased**, e.g. `cn.1`, `o.1`, `dc.1`, `dc.2`. Wrong format → `400`.
- `sans` — array of `{ element, values[] }`. `element` ∈ `rfc822name`, `dnsname`, `uri`, `ipaddress`, `othername_upn`, `othername_guid`, `registered_id`.
- `extensions` — MS extensions only: array of `{ type, value? }`, `type` ∈ `ms_sid`, `ms_template`, `ms_template_v2`.
- `ms_private_key_hash` — optional MS private-key hash passed through to issuance.
- `template_overrides` — per-request overrides of the certificate template: `ku`, `eku`, `empty_extensions`, `crldps`, `aia`, `policy`, `path_len`, `lifetime` (FiniteDuration string e.g. `"365 days"`), `backdate`, `check_pop`, `extra_csr_extensions`. NOT overridable: `privateKeyUsagePeriod`, `removeBasicConstraints`, `qcStatement`.

### `data_from` strategy (where DN/SAN/extension data is sourced)

`data_from` ∈ `api` (default) | `csr` | `apicsr`:

- `api` — take DN/SAN/extensions from the request body. **Requires `dn` or `dn_elements`** — the MCP tool rejects `api` with neither client-side before calling the server.
- `csr` — extract DN/SAN/extensions from the CSR.
- `apicsr` — use request-body values where present, else fall back to the CSR.

Owner / labels / metadata / contact do **NOT** exist on this request model (the Stream request model does not carry them).

Example (DN from request body):

```json
{
  "ca": "AXU-Intermediate",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
  "template_name": "ServerCert",
  "dn": "CN=www.example.com,O=Example",
  "sans": [
    { "element": "dnsname", "values": ["www.example.com", "example.com"] }
  ],
  "data_from": "api"
}
```

Example (everything from the CSR):

```json
{
  "ca": "AXU-Intermediate",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
  "template_name": "ServerCert",
  "data_from": "csr"
}
```

## X509 revoke — `revoke_certificate`

`POST /api/v1/lifecycle/revoke` → **200** with the now-revoked `X509Certificate` (`revoked=true`, `revocationDate` + `revocationReason` set).

Identify the certificate by **exactly one** of two mutually-required shapes:

- `certificate` — the X.509 **PEM**. If present, `serial`/`ca` are ignored.
- `serial` + `ca` — hex serial **plus** CA name. Both required together: `serial` without `ca` → `400` "/ca: expected value when '/serial' is defined" (and vice-versa). Neither shape present → `400`.

`reason` is **REQUIRED** by this tool (server-side it defaults to `unspecified`, but the MCP requires it for correct lifecycle hygiene). It is a `CFRevocationReason` RFC string — exactly these 7 values (case-insensitive on input, echoed as the RFC string on output):

| Input value            | Meaning              |
| ---------------------- | -------------------- |
| `unspecified`          | UNSPECIFIED          |
| `keyCompromise`        | KEYCOMPROMISE        |
| `cACompromise`         | CACOMPROMISE         |
| `affiliationChanged`   | AFFILIATIONCHANGE    |
| `superseded`           | SUPERSEDED           |
| `cessationOfOperation` | CESSATIONOFOPERATION |
| `certificateHold`      | CERTIFICATEHOLD      |

`removeFromCRL`, `privilegeWithdrawn`, `aACompromise` are **NOT** supported.

Behavior quirks:

- **Idempotent.** An already-revoked or already-expired cert returns `200` with its current state — no re-revocation, no error.
- Revoking a managed **self-signed root CA** cert is forbidden → `403 CA-017`.
- Not found → `404 LIFECYCLE-007`. Issuing CA expired → `403 CA-014`. No revoke permission → `403 SEC-PERM-001`.
- To know in advance whether you may revoke a given cert, read its `permissions.revoke` from `get_certificate` / `search_certificates` (true only if not revoked, not expired, and you hold revoke rights).

Examples:

```json
{
  "serial": "571868a4fa7dcdd5493399cf89b89001",
  "ca": "ISSUING_CA",
  "reason": "superseded"
}
```

```json
{ "certificate": "-----BEGIN CERTIFICATE-----\n...", "reason": "keyCompromise" }
```

## SSH enroll — `enroll_ssh_certificate`

`POST /api/v1/ssh/lifecycle/enroll` → **201** with the full `SSHCertificate` (note: `serial` is serialized as a **string**). The subject key is an OpenSSH public-key string; no CSR.

Required inputs:

- `ca` — target SSH CA name; must be ready (have a public key) and `enroll=true`. Not ready → `403 LIFECYCLE-SSH-003`; enroll disabled → `403 LIFECYCLE-SSH-002`; unknown → `404 SSH-CA-003`.
- `public_key` — the OpenSSH public key to certify, e.g. `"ssh-ed25519 AAAAC3Nza... user@host"`. Key type is checked against the template's `authorizedKeyTypes` whitelist (`ssh-rsa`, `ecdsa-sha2-nistp256/384/521`, `ssh-ed25519`).
- `template` — object: `name` (existing, **enabled** template; disabled/missing → `404 SSH-TEMPLATE-003`) plus optional overrides `type`, `lifetime`, `backdate` (FiniteDuration strings like `"12 hours"`). Each override is allowed only if the CA's `overridePermissions.{type,lifetime,backdate}` is true.
- `principals` — string array embedded in the cert (usernames for `USER`, hostnames for `HOST`). May be empty if the template's `principalPolicy` allows; otherwise validated against `min`/`max`/`regex`. Violations → `400 LIFECYCLE-SSH-004`.

`type` ∈ `USER` | `HOST` (case-sensitive UPPERCASE). If the CA enforces key unicity, a duplicate public-key thumbprint fails the enrollment.

Example:

```json
{
  "ca": "sma-rsa",
  "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host",
  "template": { "name": "user-tpl" },
  "principals": ["alice"]
}
```

With overrides (CA must permit them):

```json
{
  "ca": "sma-rsa",
  "public_key": "ssh-rsa AAAA...",
  "template": {
    "name": "user-tpl",
    "type": "USER",
    "lifetime": "12 hours",
    "backdate": "5 minutes"
  },
  "principals": ["alice", "bob"]
}
```

## SSH revoke — `revoke_ssh_certificate`

`POST /api/v1/ssh/lifecycle/revoke` → **200** with the now-revoked `SSHCertificate`. Same two-shape polymorphism as X509, but there is **NO `reason` field** for SSH revocation:

- `certificate` — the OpenSSH certificate. If present, `serial`/`ca` are ignored.
- `serial` + `ca` — `serial` is a **decimal** string (X509 serials are hex; SSH serials are decimal). Both required together; same "expected value when ... is defined" errors as X509.

Behavior: not found → `404 LIFECYCLE-SSH-007`; no permission → `403 SEC-PERM-001`. **Idempotent** — already-revoked or expired (`validBefore < now`) returns `200` with current state.

Examples:

```json
{ "serial": "12345", "ca": "sma-rsa" }
```

```json
{ "certificate": "ssh-ed25519-cert-v01@openssh.com AAAA..." }
```

## Discovering requestable templates

`list_requestable_templates` (X509) and `list_requestable_ssh_templates` (SSH) return `[{ ca, templates: [...] }, ...]` — the CA/template pairs the caller may use. Optional `permission` ∈ `enroll` | `revoke` | `search` (default `search`); each permission filters to differently-ready CAs (e.g. `enroll` only lists enroll-enabled, non-expired CAs). An empty result is normal (server returns 204 → the tools surface an empty list) when nothing is requestable for that permission.

Call these first to pick a valid `ca` + `template_name` before `enroll_certificate` / `enroll_ssh_certificate`.

## Lifecycle invariants

- **Issued certificates cannot be deleted.** Revocation is the terminal state; there is no delete-certificate tool. (Templates and CAs are separately deletable, with referential guards.)
- **Enroll is key-in, cert-out:** PKCS#10 PEM (X509) or OpenSSH pub key (SSH) goes in; a rich certificate object comes out. No server-side key generation, no PKCS#12/JKS bundle from these endpoints.
- **Revoke is idempotent and polymorphic** (PEM wins over serial+ca) for both domains; X509 requires a `reason`, SSH takes none.
- **Object identifiers are immutable** — `ca` and `template_name` are primary-key references, never renamed mid-request.
- X509 serials are lowercase **hex**; SSH serials are **decimal** strings.
