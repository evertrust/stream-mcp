How this MCP authenticates to a Stream server, the two supported auth modes, and how to discover the caller's own identity and permissions with `whoami`.

Stream has EXACTLY two ways for a programmatic client to authenticate: a **local account** (sent as `X-API-*` request headers) or an **X509 / mTLS client certificate**. There is **no OIDC login for the MCP's own auth**, no token/session flow, and no CSRF token — credentials are static and validated by Stream on **every** API request. (OIDC exists in Stream only as a _managed_ identity-provider config object you can CRUD; it is never used to authenticate this MCP.)

The auth provider is auto-selected from which env vars are set. **Priority: mTLS > local account.** Setting both mTLS and a local account makes mTLS win; setting neither is a hard startup error.

## Local account (X-API headers)

Set three env vars; they map 1:1 to headers sent on every request:

| Env var             | Header         | Meaning                                                            |
| ------------------- | -------------- | ------------------------------------------------------------------ |
| `STREAM_API_ID`     | `X-API-ID`     | local account identifier (username)                                |
| `STREAM_API_KEY`    | `X-API-KEY`    | the account password (checked against the stored hash server-side) |
| `STREAM_API_IDPROV` | `X-API-IDPROV` | identity-provider name; defaults to `local`                        |

```
STREAM_URL=https://stream.example.com
STREAM_API_ID=sbo-claude-mcp
STREAM_API_KEY=<password>
STREAM_API_IDPROV=local        # optional, defaults to "local"
```

Notes:

- `STREAM_API_ID` **and** `STREAM_API_KEY` must both be set, or local-account init throws.
- The password is the literal value in `X-API-KEY`; Stream validates it against the stored hash. There is no separate login call — the MCP just attaches the three headers to each request.
- `X-API-IDPROV` is the **name** of an enabled Local identity provider in Stream (usually `local`). It is not a credential.

## X509 / mTLS

The client certificate **is** the credential — no `X-API-*` headers are sent. The MCP presents the cert during the TLS handshake; Stream's ingress/reverse proxy forwards it to the app as the configured certificate header. Two input formats:

PEM (separate cert + key files):

```
STREAM_CLIENT_CERT=/path/to/client.crt
STREAM_CLIENT_KEY=/path/to/client.key
STREAM_CLIENT_KEY_PASSWORD=<optional>   # only if the key is encrypted
```

PKCS#12 / PFX (single bundle):

```
STREAM_CLIENT_PFX=/path/to/client.p12
STREAM_CLIENT_PFX_PASSWORD=<optional>
```

Rules enforced at startup:

- `STREAM_CLIENT_KEY` is **required** when `STREAM_CLIENT_CERT` is set.
- Set `STREAM_CLIENT_CERT`/`KEY` **or** `STREAM_CLIENT_PFX`, **not both** (hard error).
- All referenced files must exist and be readable (validated eagerly).

## TLS verification

`STREAM_VERIFY_SSL` (default `true`) controls server-cert validation. Set to `false`/`0` to disable for self-signed dev servers; leave on in production. This is independent of which auth mode you use.

## whoami — discover your identity and permissions

The `whoami` tool (read-only) returns the caller's resolved principal from `GET /api/v1/security/principals/self`. Call it first when you need to know **who you are** and **what you can do** before attempting writes or scoped lifecycle actions.

Response shape:

```json
{
  "identity": {
    "identifier": "sbo-claude-mcp",
    "name": "...", // optional, omitted when not set
    "identityProviderType": "Local", // Local | OpenId | X509
    "identityProviderName": "local"
  },
  "permissions": [{ "value": "<permission string>" }],
  "roles": ["Admin"]
}
```

- `permissions` is the **aggregated** set: the principal's direct permissions plus every permission from its assigned roles, deduped (sorted by value length). It is the effective, ready-to-check list — you do not need to expand roles yourself.
- `roles` is the list of role **names** only (not full role objects).
- `identity.name` is absent when not set on the account; do not assume it exists.
- `identityProviderType` reflects how you authenticated: `Local` (X-API headers against a Local provider), `X509` (mTLS), or `OpenId`.

## Permission string grammar

Permissions are **single strings** (not objects with action arrays). On the wire each lives in a `{ "value": "<string>" }` object. Comparison is case-insensitive; the server dedupes and sorts on write. There are two families:

CONFIGURATION — controls who can read/manage config objects (`audit`/`manage`, or `*`):

```
configuration
configuration:*
configuration:<entity2>[:<perms>]
configuration:<entity2>:<entity3>[:<perms>]
```

- level-2 entities: `security`, `keystore`, `x509`, `ssh`, `ocsp`, `timestamping`, `notification`, `system`, `license` (or `*`).
- level-3 by parent: `security` -> `credentials,identity-provider,local-identity,principal-info,role`; `x509` -> `ca,template,eku`; `ssh` -> `ca,template`; `system` -> `proxy,event,queue,configuration`; `timestamping` -> `authority,ntp,signer`. `keystore`/`ocsp`/`notification`/`license` have no level-3.
- examples: `configuration:*`, `configuration:security:role:manage`, `configuration:x509:ca:audit,manage`.

LIFECYCLE — controls certificate operations, scoped by CA and template (`enroll`/`revoke`/`search`, or `*`):

```
lifecycle:<entity>[:<cas>[:<templates>[:<perms>]]]
```

- `<entity>` is `x509` or `ssh`.
- CAs/templates must be **existing** object names or `*`; an unknown CA/template makes the permission invalid (`400`).
- examples: `lifecycle:x509:*:*:*`, `lifecycle:x509:ASA-TCA:TLS_Server:search,revoke`, `lifecycle:ssh:*:*:*`.

## Reading permission errors

When the server rejects a call, the mode of failure depends on the operation:

- **List / search** with insufficient permission returns **HTTP 204** (empty) — silent, indistinguishable from a genuinely empty collection. If a list comes back empty when you expected data, suspect a missing `audit` permission, then check `whoami`.
- **Get / write** with insufficient permission returns **HTTP 403** (explicit).

A few self-protection rules surface as `403`: you cannot edit/delete your **own** principal info, cannot delete your **own** Local identity, and cannot reset your **own** password.

## What this MCP does NOT support

- **No OIDC for the MCP's own auth.** OIDC (`OpenId`) is only a managed identity-provider config object.
- **No token/session/login flow, no CSRF token, no refresh.** Credentials are static (header strings or a cert file). The `/logout` endpoint is meaningless for header/API-key auth.
- **No second discovery query language.** Stream has exactly two query DSLs — SEQL for `search_events` and SCQL for `search_certificates`/`search_ssh_certificates` — neither of which is involved in authentication.
