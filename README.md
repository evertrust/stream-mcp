# Stream MCP Server

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/evertrust/stream-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/evertrust/stream-mcp/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io/) server for **Evertrust Stream** — a
PKI platform providing certification authorities, certificate issuance and
revocation, a validation authority (OCSP), timestamping (TSA), and an OpenSSH
certificate authority. It lets MCP-compatible LLM clients (Claude Desktop, Claude
Code, Cursor, Codex, OpenCode) stand up and operate CAs, issue/revoke X.509 and
SSH certificates, run SCQL/SEQL searches, manage keystores, OCSP/TSA signers,
notification triggers, RBAC and system configuration, and decode
X.509/CSR/CRL/PKCS#12/OpenSSH payloads — all through natural language. It targets
PKI engineers, platform teams, and security operators who want to drive Stream
without leaving their IDE or chat client.

## Tools

**153 tools across 13 domains**, each annotated with a safety tier (read-only /
idempotent / additive / destructive) and "ask before you invent a name" guidance
for smaller models.

| Domain | Tools | Highlights |
|--------|------:|------------|
| X509 Certificate Authorities | 12 | create-from-scratch, import, CSR → issue, enhance, migrate, CRL |
| X509 Certificates & Lifecycle | 6 | SCQL search/aggregate, enroll, revoke |
| X509 Certificate Templates | 5 | issuance profiles |
| Revocation (CRL & OCSP) | 10 | CRL info, OCSP signers, assign-to-CA |
| Cryptographic Storage | 12 | keystores (software/PKCS#11/AWS/Azure/GCP), keys, HSM |
| Triggers & Notifications | 6 | email/REST, expiration, external RL storage |
| System Management | 19 | config, proxies, queues, license, dictionaries, export |
| Access Control & Identity | 27 | roles, local identities, providers, credentials, whoami |
| Audit Events | 5 | SEQL search, dictionary, integrity checks |
| Utilities & Decoders | 14 | RFC5280/OpenSSH decoders, trust chains, EKUs |
| Timestamping (TSA) | 16 | authorities, signers, NTP clients |
| OpenSSH (SSH module) | 19 | CAs, templates, certificates, enroll/revoke, KRLs |
| Knowledge Base | 2 | search_docs, get_doc |

Full per-tool table with safety tiers in [docs/tools-reference.md](docs/tools-reference.md).

## Quickstart

```bash
git clone https://github.com/evertrust/stream-mcp.git
cd stream-mcp
npm install
npm run build
```

Run it (normally launched by an MCP client over stdio):

```bash
STREAM_URL=https://stream.example.com \
STREAM_API_ID=my-account \
STREAM_API_KEY='********' \
node dist/index.js
```

See [docs/installation.md](docs/installation.md) for prerequisites and the
`npx`/`bunx` launch form, and [docs/client-setup.md](docs/client-setup.md) for
Claude Desktop / Claude Code / Cursor / Codex / MCP Inspector configurations.

## Configuration

The server is configured entirely through `STREAM_*` environment variables. A
starter template lives in [.env.example](.env.example); copy it to `.env.local`
and adjust. At minimum set `STREAM_URL` and one credential set.

Authentication is **auto-detected**: a client certificate selects **X.509/mTLS**,
otherwise `STREAM_API_ID`/`STREAM_API_KEY` select **local-account** auth. OIDC is
not supported by the server. The binary name shipped by this package is
**`stream-mcp`** (declared in `package.json` `bin`). See
[docs/authentication.md](docs/authentication.md) for the full guide.

## Knowledge resources

The server embeds a knowledge base exposed at `stream://knowledge/*` URIs and via
the `search_docs` / `get_doc` tools, covering architecture, authentication, the
SCQL/SEQL query languages, CA management, lifecycle, templates, revocation,
keystores, triggers, RBAC, TSA, SSH, system admin, tool selection, and server
rules. See [docs/knowledge-resources.md](docs/knowledge-resources.md).

## Documentation

| Guide | Contents |
|-------|----------|
| [Installation](docs/installation.md) | Install methods, configuration, troubleshooting |
| [Authentication](docs/authentication.md) | Local-account and X.509/mTLS modes with env reference |
| [Client setup](docs/client-setup.md) | Claude Desktop, Claude Code, Cursor, Codex, MCP Inspector |
| [Tool reference](docs/tools-reference.md) | All 153 tools by domain with safety tiers |
| [Knowledge resources](docs/knowledge-resources.md) | `stream://knowledge/*` catalog + search tools |
| [Development](docs/development.md) | Dev setup, architecture, tests, contributing |

## Development

```bash
npm run typecheck && npm run lint && npm run test && npm run build
```

See [docs/development.md](docs/development.md) for the full guide.

## License

Copyright 2026 [Evertrust](https://www.evertrust.fr/). Licensed under the
[Apache License 2.0](LICENSE).
