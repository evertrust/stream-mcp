# Authentication

The Stream MCP server supports **two** authentication modes: **local account**
(API headers) and **X.509 / mTLS** (client certificate). OIDC is not supported
by the MCP server itself — OIDC exists only as a *managed* identity-provider
configuration object you can administer through the tools.

The mode is **auto-detected** from which environment variables are set:

1. If `STREAM_CLIENT_CERT` or `STREAM_CLIENT_PFX` is set → **mTLS**.
2. Otherwise, if `STREAM_API_ID` is set → **local account**.
3. Otherwise the server refuses to start.

No CSRF handling is required for either mode (Stream disables CSRF for
header-based auth, and X.509 responses carry no session).

## Local account (API headers)

Stream validates local-account credentials via headers on **every** request —
there is no separate login/session step. The server sends:

| Header | Source | Meaning |
|--------|--------|---------|
| `X-API-ID` | `STREAM_API_ID` | The local account identifier (username) |
| `X-API-KEY` | `STREAM_API_KEY` | The account password |
| `X-API-IDPROV` | `STREAM_API_IDPROV` (default `local`) | The identity-provider name |

```bash
STREAM_URL=https://stream.example.com
STREAM_API_ID=my-account
STREAM_API_KEY=********
STREAM_API_IDPROV=local
```

The identity-provider name must match an **enabled** provider on the instance.
The default local provider is conventionally named `local`; if your instance
names it differently, set `STREAM_API_IDPROV` accordingly.

## X.509 / mTLS (client certificate)

Provide a client certificate as PEM (cert + key) or as a PKCS#12 bundle. The
certificate **is** the credential — no API headers are sent. Stream's
ingress/reverse proxy forwards the presented client certificate to the
application as its configured certificate header.

PEM:

```bash
STREAM_URL=https://stream.example.com
STREAM_CLIENT_CERT=/path/to/client.crt
STREAM_CLIENT_KEY=/path/to/client.key
STREAM_CLIENT_KEY_PASSWORD=optional-passphrase
```

PKCS#12 / PFX:

```bash
STREAM_URL=https://stream.example.com
STREAM_CLIENT_PFX=/path/to/client.p12
STREAM_CLIENT_PFX_PASSWORD=optional-password
```

> mTLS requires the Stream deployment's ingress to be configured to request and
> forward client certificates. If the ingress does not, fall back to local-account
> auth.

## TLS verification

`STREAM_VERIFY_SSL` (default `true`) controls server-certificate verification.
Set it to `false` only for lab/QA instances with self-signed certificates; never
in production.

## Who am I

The `whoami` tool returns the authenticated principal once connected:

```json
{
  "identity": {
    "identifier": "my-account",
    "name": "My Account",
    "identityProviderType": "Local",
    "identityProviderName": "local"
  },
  "permissions": [{ "value": "configuration:*" }, { "value": "lifecycle:x509:*:*:*" }],
  "roles": ["Admin"]
}
```

### Permission strings

Permissions are strings the tools surface and the server enforces:

- `configuration:<entity>:<action>` — administer configuration objects (CAs,
  keystores, triggers, roles, …). `configuration:*` grants all.
- `lifecycle:x509:<ca>:<profile>:<action>` and
  `lifecycle:ssh:<ca>:<profile>:<action>` — enroll/revoke on specific CA/profile
  scopes (`*` wildcards each segment).

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `No authentication configured` | Set a credential set (see above). |
| `SEC-AUTH-002` invalid credentials | Wrong identifier/password, or wrong `STREAM_API_IDPROV`. |
| `SEC-AUTH-007` invalid identity provider | `STREAM_API_IDPROV` is not an enabled provider name. |
| `SEC-PERM-001` | The principal lacks the permission for the operation. |
| TLS handshake failure | Check `STREAM_URL` scheme/host; for labs set `STREAM_VERIFY_SSL=false`. |
