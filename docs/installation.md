# Installation

The Stream MCP server is a stdio MCP server. It runs anywhere Node.js ≥ 22.19
(or Bun) is available.

## Prerequisites

- **Node.js ≥ 22.19** (or **Bun 1.x+**).
- Network access to a Stream 2.1 instance and valid credentials (see
  [authentication.md](authentication.md)).

## From source

```bash
git clone https://github.com/evertrust/stream-mcp.git
cd stream-mcp
npm install
npm run build      # produces dist/index.js
```

Run it:

```bash
STREAM_URL=https://stream.example.com \
STREAM_API_ID=my-account \
STREAM_API_KEY='********' \
node dist/index.js
```

The server speaks MCP over **stdio** — it is normally launched by an MCP client
rather than run by hand. See [client-setup.md](client-setup.md).

## Via npx / bunx

Once published, the server can be launched without a local checkout:

```bash
bunx @evertrust/stream-mcp     # or: npx -y @evertrust/stream-mcp
```

The binary name declared in `package.json` is **`stream-mcp`** — use that exact
name in client configurations.

## Configuration

All configuration is through `STREAM_*` environment variables. A starter
template lives in [`.env.example`](../.env.example); copy it to `.env.local` and
adjust. The required minimum is `STREAM_URL` plus one set of credentials.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STREAM_URL` | yes | `https://localhost` | Base URL of the Stream instance |
| `STREAM_API_ID` | local auth | — | Local account identifier |
| `STREAM_API_KEY` | local auth | — | Local account password |
| `STREAM_API_IDPROV` | no | `local` | Identity-provider name |
| `STREAM_CLIENT_CERT` / `STREAM_CLIENT_KEY` | mTLS | — | Client cert + key (PEM) |
| `STREAM_CLIENT_KEY_PASSWORD` | no | — | Key passphrase |
| `STREAM_CLIENT_PFX` / `STREAM_CLIENT_PFX_PASSWORD` | mTLS | — | PKCS#12 bundle + password |
| `STREAM_VERIFY_SSL` | no | `true` | Verify the server TLS certificate |
| `STREAM_TIMEOUT` | no | `30` | Per-request timeout (seconds) |
| `STREAM_EXPORT_TIMEOUT` | no | `120` | Timeout for large exports (seconds) |
| `STREAM_LOG_LEVEL` | no | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

See [authentication.md](authentication.md) for the full credential guide.

## Verifying it works

With credentials set, the server authenticates lazily on the first tool call.
A quick smoke check is the `whoami` tool, which returns the resolved principal
(identifier, roles, permissions). Logs are written to stderr as JSON lines; set
`STREAM_LOG_LEVEL=DEBUG` for verbose request tracing.

## Troubleshooting

- **`No authentication configured`** — set `STREAM_API_ID`+`STREAM_API_KEY`, or
  `STREAM_CLIENT_CERT`+`STREAM_CLIENT_KEY` (or `STREAM_CLIENT_PFX`).
- **`SEC-AUTH-002 invalid credentials`** — wrong identifier/password, or wrong
  `STREAM_API_IDPROV` (the local provider is usually named `local`).
- **`SEC-AUTH-007 invalid identity provider`** — `STREAM_API_IDPROV` does not
  match an enabled provider name on the instance.
- **TLS errors against a lab instance** — set `STREAM_VERIFY_SSL=false` (never in
  production).
