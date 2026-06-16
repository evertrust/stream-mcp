Access control and identity administration in Stream. Five object families under `/api/v1/security/*`: **roles** (named permission bundles), **local identities** (local accounts), **identity providers** (Local + OpenId config), **credentials** (write-only secrets), and **principal infos** (per-principal authorizations). Plus `whoami`. All objects follow Stream's universal rules: the name/identifier is an **immutable primary key**, updates are **full-replace** (the scaffold does GET-strip-merge-PUT), secrets are **write-only** (sent in, redacted out), and empty lists return **204 → empty list**.

Read tools need the matching `audit` (or `manage`) permission; create/update/delete need `manage`. On a list/search, missing permission yields 204 (empty); on a get/write it yields 403.

## Permission string grammar

A permission is a single string with parts divided by `:`, comma-lists inside a part, and `*` as wildcard. Comparison is case-insensitive. Roles and principal infos carry `permissions` as an array of strings (the MCP wraps each into the `{ "value": "<string>" }` wire shape for you; the server dedupes + sorts). Invalid permissions reject the whole upsert with `ROLE-002` / `PRINCIPAL-INFO-002` (400).

Two families:

**Configuration permissions** — `configuration[:<entity2>[:<entity3>][:<perms>]]` where `<perms>` is a comma-list of `audit` / `manage` (or `*`).

- Level-2 entities: `security`, `keystore`, `x509`, `ssh`, `ocsp`, `timestamping`, `notification`, `system`, `license` (or `*`).
- Level-3 by parent: `security` → `credentials` `identity-provider` `local-identity` `principal-info` `role`; `x509` → `ca` `template` `eku`; `ssh` → `ca` `template`; `system` → `proxy` `event` `queue` `configuration`; `timestamping` → `authority` `ntp` `signer`. (`keystore`, `ocsp`, `notification`, `license` have no level-3.)
- Examples: `configuration:*`, `configuration:security:role:manage`, `configuration:x509:ca:audit,manage`.

**Lifecycle permissions** — `lifecycle:<entity>[:<cas>[:<templates>[:<perms>]]]`.

- `<entity>` is `x509` or `ssh`.
- `<cas>` = `*` or a comma-list of **existing CA names**; `<templates>` = `*` or **existing template names**; `<perms>` = `*` or a comma-list of `enroll` / `revoke` / `search`.
- Examples: `lifecycle:x509:*:*:*`, `lifecycle:ssh:*:*:*`, `lifecycle:x509:ASA-TCA:TLS_Server:search,revoke`.

> Lifecycle CAs/templates are **cross-referenced against live objects**. A permission naming a CA or template that does not exist makes `create_role` / `update_role` / `create_principal_info` / `update_principal_info` fail with 400. Create the CA/template first.

## Roles

Tools: `list_roles`, `get_role`, `create_role`, `update_role`, `delete_role`. A role is `{ name, description?, permissions[] }`; `name` is the immutable key. `update_role` is full-replace — omitted optional fields are reset; resend the full `permissions` list. `delete_role` also removes the role from every principal info that referenced it.

```jsonc
// create_role
{
  "name": "tls-operator",
  "permissions": [
    "lifecycle:x509:*:TLS_Server:enroll,revoke",
    "configuration:security:role:audit",
  ],
}
```

Errors: `ROLE-002` invalid (400), `ROLE-003` not found (404), `ROLE-004` already exists (403).

## Local identities

Tools: `list_local_identities`, `get_local_identity`, `create_local_identity`, `update_local_identity`, `delete_local_identity`, `reset_local_identity_password`. The `idField` is `identifier` (immutable; no leading/trailing whitespace). A local account is `{ identifier, name?, expires? }`.

**The password is server-generated, never settable.** On `create_local_identity` and `reset_local_identity_password` the server returns a fresh random password **once, in clear** — capture it immediately; it is never retrievable again. The `hash` and `password` fields are stripped from every read and from update bodies. `update_local_identity` **cannot change the password** (use the reset tool).

Self-protection: you **cannot delete your own** local identity (`LOCAL-ID-008`, 403) and **cannot reset your own** password (`SEC-PERM-001`, 403). Creating a local identity requires an **enabled Local identity provider** to exist (`LOCAL-ID-009`, 400).

```jsonc
// create_local_identity  ->  response contains "password":"<one-time-clear>"
{ "identifier": "svc-deploy", "name": "Deploy service account" }
// reset_local_identity_password
{ "identifier": "svc-deploy" }   // -> new one-time password in response
```

Errors: `LOCAL-ID-002` invalid (400), `LOCAL-ID-003` not found (404), `LOCAL-ID-004` exists (400), `LOCAL-ID-008` self-delete (403), `LOCAL-ID-009` provider missing/disabled (400).

## Identity providers

Tools: `list_identity_providers`, `get_identity_provider`, `create_identity_provider`, `update_identity_provider`, `delete_identity_provider`. Polymorphic on `type`. Only **two creatable types** via these tools: `Local` and `OpenId`. `name` is the immutable key, and `"x509"` (case-insensitive) is **reserved/rejected**.

> These are **config objects only**. The MCP's own auth is LOCAL ACCOUNT (`X-API-ID` / `X-API-KEY` / `X-API-IDPROV` headers) or X509/mTLS. **OpenId here is NOT used to authenticate to the MCP** — it is an identity-provider configuration you manage, nothing more.

Common fields: `name`, `enabled` (bool), `enabledOnUI` (bool), optional `proxy` (must reference an existing HTTP proxy).

`type: "Local"` — adds optional `passwordPolicy` (a policy/regex name). No `proxy`.

`type: "OpenId"` — adds:

- `providerMetadataUrl` (required, the OIDC discovery URL)
- `scope` (required, space-separated, e.g. `"openid email profile"`)
- `credentials` (effectively required: name of a `password` credential whose `target` is `openid`; validated to exist)
- `identifierClaim` (default `"{{email}}"`), `nameClaim` (default `"{{name}}"`) — template strings
- `timeout` (duration string, default `"5 seconds"`), `proxy`

```jsonc
// create_identity_provider (OpenId)
{
  "type": "OpenId",
  "name": "entra",
  "enabled": true,
  "enabledOnUI": true,
  "providerMetadataUrl": "https://login.microsoftonline.com/<tid>/v2.0/.well-known/openid-configuration",
  "scope": "openid email profile",
  "credentials": "OpenID-entra",
  "identifierClaim": "{{email}}",
  "nameClaim": "{{name}}",
}
```

`X509` is **not** a dynamic provider and is rejected by these tools. `delete_identity_provider` fails with `SEC-ID-PROV-006` (400) if the provider is still referenced. Errors: `-002` invalid (400), `-003` not found (404), `-004` exists (400), `-006` invalid reference (400).

## Credentials (write-only secrets)

Tools: `list_credentials` (optional `type` / `target` filters), `get_credential`, `create_credential`, `update_credential`, `delete_credential`. Polymorphic on `type`. `name` is the immutable key, and **`target` is immutable on update** (`'target' cannot be edited` → 400).

The secret payload is **write-only**: send it on create/update, but it always comes back redacted (`{}`). On update, **omit the secret to keep the previous value**; only send it to change it. A credential whose `expires` is already in the past is rejected on create (400).

Types and their secret shape:

| `type`     | valid `target`                                                | secret field                                                        |
| ---------- | ------------------------------------------------------------- | ------------------------------------------------------------------- |
| `password` | `akv` `aws` `ldap` `openid` `rest` `ssh` `stream` (not `gcp`) | `login` + `password: {clear}`                                       |
| `raw`      | `gcp` `rest`                                                  | `secret: {clear}`                                                   |
| `ssh`      | `ssh` only                                                    | `login` + `key: {clear}` (validated as a parseable SSH private key) |
| `x509`     | `rest` `stream`                                               | `store: { certificate: "<PEM>", keyPair: {clear} }`                 |

For `x509`, the cert public key must match the private key (else 400); `expires` is set by the server from the cert's `notAfter`. Credentials can carry an optional `triggers` object (e.g. an `onCredentialsExpiration` trigger). The `keyPair` / `password` / `secret` / `key` always read back as `{}`.

```jsonc
// create_credential (password for an OIDC provider)
{
  "type": "password",
  "name": "OpenID-entra",
  "target": "openid",
  "login": "<client-id>",
  "password": { "clear": "<client-secret>" },
}
```

Errors: `CREDENTIALS-002` invalid (400, e.g. bad target/expired/bad SSH key/cert mismatch), `-003` not found (404), `-004` exists (403), `-005` referenced (400, blocks delete when a keystore / identity provider / trigger uses it).

## Principal infos (authorizations)

Tools: `get_principal_info`, `create_principal_info`, `update_principal_info`, `delete_principal_info`, `search_principal_infos`. **There is no list endpoint** — use `search_principal_infos` (empty body returns all, paged). A principal info binds a principal's `identifier` to direct `permissions[]` and `roles[]`.

- `identifier` immutable key (not blank).
- `permissions` — same grammar as roles (incl. CA/template cross-refs).
- `roles` — array of role **names**, each must reference an **existing role** (else 400).
- `creationDate`, `lastAuthentication`, `lastModification` are **server-managed** (stripped from write bodies, preserved/updated by the server).

Self-protection: you **cannot create/update/delete your own** principal info (`Cannot edit self principal info`, 403).

```jsonc
// create_principal_info
{
  "identifier": "svc-deploy",
  "roles": ["tls-operator"],
  "permissions": ["configuration:x509:ca:audit"],
}
```

`search_principal_infos` body — all fields optional: `identifier` (substring/regex), `role` (filter by role name), `strictSearch`, `sortedBy` (`element` ∈ `identifier` | `role`), `pageIndex`, `pageSize`, `withCount`. Response: `{ results: [...], pageIndex, pageSize, count?, hasMore }` (`count` only when `withCount: true`). Use `identifier`, **not** `query`, for filtering.

```jsonc
// search_principal_infos  (all principal infos, first page)
{ "pageIndex": 1, "pageSize": 50 }
```

Errors: `PRINCIPAL-INFO-002` invalid perms/roles (400), `-003` not found (404), `-004` exists (400).

## whoami

`whoami` returns the **caller's** resolved principal — call it first to discover who you are and what you can do. Shape:

```jsonc
{ "identity": { "identifier": "sbo-claude-mcp",
                "identityProviderType": "Local", "identityProviderName": "local" },
  "permissions": [ { "value": "configuration:*" },
                   { "value": "lifecycle:x509:*:*:*" } ],   // direct + role perms, merged/deduped
  "roles": [ "Admin" ] }                                     // role names only
}
```

`permissions` is the **aggregated** set (direct permissions + every permission from the assigned roles, deduped). `roles` lists role names only. `identity.name` is absent when not set. There is no usable logout for API-key auth.
