# Stream MCP Server

`@evertrust/stream-mcp` — a [Model Context Protocol](https://modelcontextprotocol.io)
server that exposes the **Evertrust Stream 2.1** PKI platform (certification
authorities, certificates, revocation, timestamping, SSH, and the supporting
configuration) to AI agents.

It mirrors the architecture of a proven layered MCP architecture: TypeScript over stdio,
`@modelcontextprotocol/sdk`, `undici`, and `zod`. Every tool's request/response
contract is traced to the Stream Scala source and verified live against a running
instance.

## Features

- **151 tools** across all four Stream modules plus supporting config.
- **Embedded knowledge** resources (`stream://knowledge/*`) and a `search_docs`
  tool so the agent can look up Stream concepts and query syntax.
- **Two auth modes**: local account (API headers) and X.509 / mTLS. No OIDC.
- Safe by construction: immutable-name guards, full-replace update cycle,
  secret redaction, destructive-action echo confirmation, structured errors.

### Tool domains

| Domain | Tools | Examples |
|--------|-------|----------|
| X509 CA management | 12 | `list_cas`, `create_ca`, `generate_ca_csr`, `issue_ca`, `enhance_ca`, `migrate_ca`, `generate_crl`, `upload_crl` |
| X509 certificates + lifecycle | 6 | `search_certificates`, `aggregate_certificates`, `get_certificate`, `enroll_certificate`, `revoke_certificate` |
| X509 templates | 5 | `list_templates`, `create_template`, `update_template`, `delete_template` |
| Revocation (CRL + OCSP) | 10 | `list_crls`, `update_crl_next_refresh`, `create_ocsp_signer`, `generate_ocsp_signer_csr`, `assign_ocsp_signer_to_ca` |
| Crypto (keystores/keys/HSM) | 12 | `create_keystore`, `create_key`, `find_ca_keys`, `get_hsm_info`, `get_hsm_slots` |
| Triggers / notifications | 6 | `list_triggers`, `create_trigger`, `update_trigger`, `test_trigger` |
| System management | 19 | `upsert_system_configuration`, `create_proxy`, `create_queue`, `get_license_info`, `get_key_types`, `export_configuration` |
| RBAC / security | 27 | `whoami`, `create_role`, `create_local_identity`, `reset_local_identity_password`, `create_credential`, `create_identity_provider` |
| Audit events | 5 | `search_events`, `get_event`, `get_event_dictionary`, `run_event_integrity_check` |
| Utilities / decoders | 14 | `detect_file`, `decode_x509`, `decode_csr`, `decode_crl`, `extract_pkcs12`, `get_trust_chain`, `list_ekus` |
| TSA (timestamping) | 16 | `create_tsa_authority`, `create_tsa_signer`, `generate_tsa_signer_csr`, `create_ntp_client` |
| SSH (OpenSSH) | 19 | `create_ssh_ca`, `generate_krl`, `create_ssh_template`, `enroll_ssh_certificate`, `revoke_ssh_certificate` |

### Knowledge resources

Served as `stream://knowledge/*` (and consult via the `search_docs` tool):
`architecture`, `authentication`, `query-languages`, `ca-management`,
`lifecycle`, `templates`, `revocation`, `keystores`, `triggers`, `rbac`, `tsa`,
`ssh`, `system-admin`, `tool-selection`, `server-rules`.

> Stream has exactly two query languages: **SEQL** (Stream Events Query Language,
> for `search_events`) and **SCQL** (Stream Certificates Query Language, for
> `search_certificates` / `search_ssh_certificates`).

## Installation

```bash
npm install      # install dependencies
npm run build    # bundle to dist/index.js
```

Requires Node.js ≥ 24.10 (or Bun).

## Configuration

All configuration is via `STREAM_*` environment variables (see `.env.example`).

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STREAM_URL` | yes | `https://localhost` | Base URL of the Stream instance |
| `STREAM_API_ID` | local auth | — | Local account identifier (username) |
| `STREAM_API_KEY` | local auth | — | Local account password |
| `STREAM_API_IDPROV` | no | `local` | Identity-provider name |
| `STREAM_CLIENT_CERT` / `STREAM_CLIENT_KEY` | mTLS | — | Client cert + key (PEM) |
| `STREAM_CLIENT_KEY_PASSWORD` | no | — | Key passphrase |
| `STREAM_CLIENT_PFX` / `STREAM_CLIENT_PFX_PASSWORD` | mTLS | — | PKCS#12 bundle + password |
| `STREAM_VERIFY_SSL` | no | `true` | Verify the server TLS certificate |
| `STREAM_TIMEOUT` | no | `30` | Request timeout (seconds) |
| `STREAM_LOG_LEVEL` | no | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

**Authentication** is auto-detected: a client cert/PFX selects mTLS; otherwise
`STREAM_API_ID`/`STREAM_API_KEY` select local-account auth. OIDC is not supported.

### MCP client configuration

```jsonc
{
  "mcpServers": {
    "stream": {
      "command": "node",
      "args": ["/path/to/stream-mcp/dist/index.js"],
      "env": {
        "STREAM_URL": "https://stream.example.com",
        "STREAM_API_ID": "my-account",
        "STREAM_API_KEY": "••••••••",
        "STREAM_API_IDPROV": "local"
      }
    }
  }
}
```

## Development

```bash
npm run dev          # run from source (tsx)
npm run typecheck    # tsc --noEmit
npm run test         # unit tests (vitest)
npm run lint         # eslint
npm run build        # tsup bundle
```

### Live (e2e) tests

E2E tests run against a real Stream instance and are gated on `STREAM_E2E_*`
variables (place them in `.env.local`, which is git-ignored):

```bash
STREAM_E2E_URL=https://stream.qa.example.com
STREAM_E2E_API_ID=...
STREAM_E2E_API_KEY=...
```

```bash
npm run test:e2e
```

## Project layout

```
src/
  index.ts            # server entry (stdio)
  settings.ts         # STREAM_* env -> validated config
  auth/               # local-account + mTLS providers
  client/             # StreamClient (undici), errors, retry
  tools/              # one folder per domain + registry + scaffold/helpers
  resources/          # stream://knowledge/* catalog + markdown
docs/
  audit/              # per-domain REST API contracts (ground truth)
  superpowers/        # design spec + implementation plan
```

## License

See [LICENSE](./LICENSE).
