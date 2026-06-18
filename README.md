# stream-mcp

[![npm version](https://img.shields.io/npm/v/@evertrust/stream-mcp.svg)](https://www.npmjs.com/package/@evertrust/stream-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/evertrust/stream-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/evertrust/stream-mcp/actions/workflows/ci.yml)

An [MCP](https://modelcontextprotocol.io/) server for [Evertrust Stream](https://www.evertrust.fr/) - a PKI platform that runs certification authorities, a validation authority (OCSP), a timestamping authority (TSA), and an OpenSSH certificate authority. It lets MCP-compatible LLM clients (Claude Desktop, Claude Code, Cursor, Codex, OpenCode) stand up and operate CAs, issue/renew/revoke X.509 and SSH certificates, run SCQL/SEQL searches over certificates and audit events, manage keystores, OCSP/TSA signers, notification triggers, RBAC and system configuration, and decode X.509/CSR/CRL/PKCS#12/OpenSSH payloads - all through natural language. It is aimed at PKI engineers, platform teams and security operators who want to operate Stream without leaving their IDE or chat client.

## Why knowledge-first?

Most MCP servers hand an LLM a list of tools and leave it to figure out the domain. stream-mcp ships **15 embedded knowledge topics** (served as `stream://knowledge/*` resources and reachable through the `search_docs` / `get_doc` tools) covering Stream's architecture, the SEQL/SCQL query languages, CA-management workflows (create-from-scratch vs import), certificate lifecycle, templates, revocation, keystores, triggers, RBAC, TSA, SSH, system administration, a deterministic tool-selection playbook, and the server's operating rules. MCP clients can read these to ground tool selection and payload construction, but the server does not force a preload step.

## Features

- **157 tools across 13 domains**, each annotated with a safety tier (`read-only`, `idempotent`, `additive`, `destructive`) surfaced as MCP tool annotations.
- **Knowledge catalog**: 15 topic URIs (with auto-generated section URIs for the longer guides) plus `search_docs` / `get_doc` tools.
- **Two authentication modes**: local account (API headers) and mutual TLS (PEM or PKCS#12). No OIDC.
- **Query languages**: SCQL (Stream Certificates Query Language) for certificate search/aggregate and SEQL (Stream Events Query Language) for the audit log, documented in `stream://knowledge/query-languages`.
- **Crypto decoding**: parse X.509, PKCS#10 CSR, CRL, PKCS#12, and OpenSSH public keys to structured JSON without leaving the chat.
- **CA from scratch or imported**: create managed root/subordinate CAs (generate key, CSR, issue) or import external CAs, with full CRL and OCSP-signer management.
- **Confirmation safeguards**: destructive tools require an `expected_<id>` echo that must match the target; certificate revocation requires an `expected_serial` confirmation; an SSRF guard blocks REST-trigger URLs that point at internal hosts.
- **Secret hygiene**: keys, PINs, PKCS#12 material and credential secrets are write-only and redacted from tool output; one-time generated passwords are surfaced exactly once on create/reset.

Tool counts per domain:

| Domain                          | Tools | Highlights                                                                 |
| ------------------------------- | ----: | ------------------------------------------------------------------------- |
| Access control & identity       |    28 | roles, local identities, identity providers, credentials, `whoami`        |
| System management               |    19 | config, HTTP proxies, queues, license, dictionaries, AsciiDoc export      |
| OpenSSH (SSH module)            |    20 | SSH CAs, templates, certificate search/enroll/revoke, KRLs                 |
| Timestamping (TSA)             |    16 | TSA authorities, signers (+ CSR), NTP clients                             |
| Utilities & decoders            |    14 | X.509/CSR/CRL/PKCS#12/OpenSSH decoders, trust chains, EKUs                 |
| X.509 certificate authorities   |    12 | create-from-scratch, import, CSR, issue, enhance, migrate, CRL upload      |
| Cryptographic storage           |    12 | keystores (software/PKCS#11/AWS/Azure/GCP), keys, HSM introspection        |
| Revocation (CRL & OCSP)        |    12 | CRL info + published CRL/AIA fetch, OCSP signers (+ CSR), assign-to-CA     |
| X.509 certificates & lifecycle  |     6 | SCQL search/aggregate, enroll, revoke, requestable templates              |
| Triggers & notifications        |     6 | email / REST notifications, expiration triggers, dry-run test             |
| X.509 certificate templates     |     5 | issuance-profile CRUD                                                      |
| Audit events                    |     5 | SEQL search, dictionary, integrity check + reports                        |
| Knowledge base                  |     2 | `search_docs`, `get_doc`                                                   |

Full per-tool table with safety tiers in [docs/tools-reference.md](docs/tools-reference.md).

## Prerequisites

- [Bun](https://bun.sh/) 1.x+ (recommended) or Node.js >= 22.19
- An Evertrust Stream 2.1 instance
- A local account (username/password) or a client certificate for that instance

## Install

### Option 1 - run from npm with bunx or npx

No install needed:

```bash
bunx @evertrust/stream-mcp
# or
npx -y @evertrust/stream-mcp
```

### Option 2 - from source

```bash
git clone https://github.com/evertrust/stream-mcp.git
cd stream-mcp
bun install
bun run build
node dist/index.js
```

### Option 3 - prebuilt standalone binary

Each GitHub release attaches self-contained binaries (no Node/Bun required) for
Linux (x64/arm64), macOS (x64/arm64), and Windows (x64). Download the one for
your platform from the [Releases](https://github.com/evertrust/stream-mcp/releases)
page, make it executable, and run it directly.

The server speaks MCP over **stdio** - it is normally launched by an MCP client rather than run by hand (see [MCP client setup](#mcp-client-setup)).

## Configuration

The server is configured entirely through `STREAM_*` environment variables. A starter template lives in [.env.example](.env.example); copy it to `.env.local` and adjust.

The server auto-detects the authentication mode based on which variables are set. Priority order: **mTLS > local account**.

### Connection and authentication

| Variable                       | Required?           | Default              | Description                                                                                |
| ------------------------------ | ------------------- | -------------------- | ----------------------------------------------------------------------------------------- |
| `STREAM_URL`                   | Yes                 | `https://localhost`  | Base URL of your Stream instance. Trailing slash is stripped automatically.               |
| `STREAM_API_ID`                | Local-account mode  |                      | Local account identifier (username).                                                      |
| `STREAM_API_KEY`               | Local-account mode  |                      | Local account password.                                                                   |
| `STREAM_API_IDPROV`            | No                  | `local`              | Identity-provider name the account belongs to (the local provider is usually `local`).    |
| `STREAM_CLIENT_CERT`           | mTLS (PEM) mode     |                      | Filesystem path to a PEM client certificate.                                              |
| `STREAM_CLIENT_KEY`            | mTLS (PEM) mode     |                      | Filesystem path to the matching PEM private key.                                          |
| `STREAM_CLIENT_KEY_PASSWORD`   | No                  |                      | Decryption password for an encrypted PEM private key.                                     |
| `STREAM_CLIENT_PFX`            | mTLS (PFX) mode     |                      | Filesystem path to a PKCS#12 / PFX bundle.                                                |
| `STREAM_CLIENT_PFX_PASSWORD`   | No                  |                      | Decryption password for the PKCS#12 bundle.                                               |
| `STREAM_VERIFY_SSL`            | No                  | `true`               | Set to `false` or `0` to skip TLS verification on the Stream endpoint (development only). |
| `STREAM_TIMEOUT`               | No                  | `30`                 | HTTP request timeout in seconds for standard API calls.                                   |
| `STREAM_EXPORT_TIMEOUT`        | No                  | `120`                | Timeout in seconds for long-running endpoints such as the AsciiDoc config export.         |
| `STREAM_LOG_LEVEL`             | No                  | `INFO`               | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`.                                               |
| `STREAM_TESTED_VERSIONS`       | No                  | `2.1`                | Comma-separated list of Stream versions known to fully work with this build.             |
| `STREAM_WARN_VERSIONS`         | No                  | _(empty)_            | Comma-separated list of versions that are likely to work but emit a warning instead of an "untested" caution. |

### Security hardening (optional)

| Variable                        | Default | Description                                                                                                   |
| ------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| `STREAM_ALLOW_INTERNAL_URLS`    | `false` | Allow REST notification triggers to target loopback/link-local/private hosts. Blocked by default (SSRF guard). |
| `STREAM_HSM_LIBRARY_ALLOWLIST`  |         | Comma-separated absolute paths; when set, the HSM tools may only load these PKCS#11 libraries.                |

### Development and testing

These variables are read by the test suite only and never by the server itself:

| Variable                  | Used by                              | Description                                                       |
| ------------------------- | ------------------------------------ | ---------------------------------------------------------------- |
| `STREAM_E2E_URL`          | `test:e2e`, `test:scenarios`         | Base URL of the Stream instance for live tests.                  |
| `STREAM_E2E_API_ID`       | `test:e2e`, `test:scenarios`         | Local account identifier for live tests.                        |
| `STREAM_E2E_API_KEY`      | `test:e2e`, `test:scenarios`         | Local account password for live tests.                          |
| `STREAM_LLM_LIVE`         | `test:llm:live`                      | Set to `1` to opt into the paid, model-driven smoke suite.       |
| `STREAM_LLM_LIVE_MODEL`   | `test:llm:live`                      | Model id for the live smoke suite (default `claude-sonnet-4-5`). |

## MCP client setup

The binary name shipped by this package is **`stream-mcp`** (declared in `package.json` `bin`). Use that exact name in every client configuration.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "stream": {
      "command": "bunx",
      "args": ["@evertrust/stream-mcp"],
      "env": {
        "STREAM_URL": "https://stream.example.com",
        "STREAM_API_ID": "<your-username>",
        "STREAM_API_KEY": "<your-password>",
        "STREAM_API_IDPROV": "local"
      }
    }
  }
}
```

### Claude Code

Create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "stream": {
      "command": "bunx",
      "args": ["@evertrust/stream-mcp"],
      "env": {
        "STREAM_URL": "https://stream.example.com",
        "STREAM_API_ID": "<your-username>",
        "STREAM_API_KEY": "<your-password>",
        "STREAM_API_IDPROV": "local"
      }
    }
  }
}
```

### Cursor

Create `.cursor/mcp.json` in your project root (or `~/.cursor/mcp.json` for global access) with the same `mcpServers` block as Claude Code.

For Codex, OpenCode, and MCP Inspector configurations, see [docs/client-setup.md](docs/client-setup.md). To run a local build instead of `bunx`, set `command` to `node` and `args` to `["/abs/path/to/stream-mcp/dist/index.js"]`.

## Authentication modes

- **Local account** - the default mode. Stream validates the account on every request via the `X-API-ID` / `X-API-KEY` / `X-API-IDPROV` headers (there is no separate login step). Set `STREAM_API_ID`, `STREAM_API_KEY`, and `STREAM_API_IDPROV` (the local provider is conventionally named `local`).
- **Mutual TLS (PEM)** - use when your Stream ingress enforces client certificates and you have separate cert and key files. Set `STREAM_CLIENT_CERT`, `STREAM_CLIENT_KEY`, and optionally `STREAM_CLIENT_KEY_PASSWORD`. The ingress forwards the presented certificate to Stream as the configured certificate header.
- **Mutual TLS (PKCS#12 / PFX)** - same as above but using a combined `.p12` / `.pfx` bundle. Set `STREAM_CLIENT_PFX` and optionally `STREAM_CLIENT_PFX_PASSWORD`.

OIDC is **not** supported as a sign-in mode for the MCP server (OIDC exists only as a *managed* identity-provider configuration object you can administer through the tools).

See [docs/authentication.md](docs/authentication.md) for the full step-by-step guide and troubleshooting tips.

## Tool catalog overview

The 157 tools are grouped into 13 domains. Each tool ships with explicit guidance for smaller models and clearly distinguishes mandatory from optional inputs. The table above lists per-domain counts; [docs/tools-reference.md](docs/tools-reference.md) has the full per-tool table with safety tiers and one-line descriptions.

Knowledge resources are exposed at `stream://knowledge/*` URIs. See [docs/knowledge-resources.md](docs/knowledge-resources.md) for the full catalog.

## Sample prompts

These natural language prompts work with any connected LLM.

### Certification authorities

```
Stand up a new managed root CA from scratch called "Acme-Root", then generate its CSR and self-issue it.
```

```
Import our partner's CA certificate as an external CA and point it at their CRL distribution URL.
```

```
List the certificate authorities and show me which ones are managed vs external.
```

### Certificate search and lifecycle

```
Find all certificates expiring in the next 30 days.
```

```
How many certificates are there grouped by template?
```

```
Enroll a certificate from this PKCS#10 CSR using the "WebServer" template.
```

```
Revoke the certificate with serial deadbeef on CA "Acme-Root", reason keyCompromise.
```

### Revocation services

```
Show me the CRL status for every CA.
```

```
Create an OCSP signer backed by the "ocsp" keystore and assign it to "Acme-Root".
```

### Keystores and decoding

```
List the keystores and generate an RSA-4096 key on the software keystore.
```

```
Decode this X.509 certificate PEM and tell me its key usages and SANs.
```

```
Extract the certificate and private key from this PKCS#12 bundle.
```

### Timestamping and SSH

```
Create a timestamping authority backed by a new TSA signer.
```

```
Create an SSH user CA and list the SSH certificate templates.
```

### Audit, system, and identity

```
Search the audit log for recent certificate revocations.
```

```
What Stream version is running and which modules are licensed?
```

```
Who am I authenticated as, and what permissions do I have?
```

```
Create a local account for a new operator and return its one-time password.
```

## Troubleshooting

- **`No authentication configured`** - set `STREAM_API_ID` + `STREAM_API_KEY` for local-account auth, or `STREAM_CLIENT_CERT` + `STREAM_CLIENT_KEY` (or `STREAM_CLIENT_PFX`) for mTLS.
- **`SEC-AUTH-002` invalid credentials** - wrong identifier/password, or the wrong `STREAM_API_IDPROV` (the local provider is usually `local`).
- **`SEC-AUTH-007` invalid identity provider** - `STREAM_API_IDPROV` does not match an enabled provider name on the instance.
- **`SEC-PERM-001`** - the authenticated principal lacks the required permission for the operation.
- **Empty lists / `STREAMQL-001`** - Stream returns HTTP `204` for empty (or forbidden) collections, which the tools surface as an empty list. For certificate search the SCQL query may not be empty (use `id exists` to match all); for the audit log, SEQL omits the query to match all.
- **TLS handshake failures** - check `STREAM_URL` uses `https://` and that the Stream CA is trusted by your system store; for development only, set `STREAM_VERIFY_SSL=false`.
- **Version compatibility warnings** - the server logs a warning when the connected Stream version is in `STREAM_WARN_VERSIONS`. Functionality is best-effort on those versions.

## Compatibility

| Stream version | Status                                                        |
| -------------- | ------------------------------------------------------------- |
| 2.1            | Tested (full feature set)                                     |
| Other          | Untested — the server logs a caution at startup and proceeds. Add a version to `STREAM_WARN_VERSIONS` to downgrade that caution. |

## What is not supported

- **OIDC sign-in for the MCP server** - only local-account and mTLS auth are supported (OIDC providers can be *managed* as configuration objects, but not used to authenticate the MCP itself).
- **Protocol responder traffic** - the OCSP (`/ocsp`) and TSA (`/tsa`) endpoints are wire-protocol services; this MCP manages their *configuration* (signers, CAs), not the responder traffic. The published CRL / AIA / KRL artifacts can be *fetched* read-only (`get_published_crl` / `get_published_aia` / `get_published_krl`) for inspection.
- **Deleting issued certificates** - Stream exposes no API to delete an issued certificate; revocation is the terminal state.

## Contributing

PRs welcome. Before opening a pull request, run `bun run format:check && bun run lint && bun run typecheck && bun run build && bun run test` (source `.env.local` first to additionally exercise the live e2e and grounded LLM tiers). Keep commits to one-line conventional messages (`type: description`).

For local setup, project layout, architecture, how to add a tool, and the full test guide (unit, e2e, and LLM tiers), see [docs/development.md](docs/development.md).

## Safety and trust caveats

> [!CAUTION]
> **Experimental software** - this MCP server is experimental and should only be used for exploratory purposes at this time.
>
> **Permissions** - the MCP server authenticates as the configured account and the AI agent operates with that account's full permissions. Evertrust recommends against granting AI agents highly privileged access to the PKI to prevent unintended incidents.
>
> **No guaranteed boundaries** - while the MCP server attempts to enforce permission boundaries between the user and the AI agent, this may not work in all cases. Users bear sole responsibility for actions taken by the AI agent on their behalf.
>
> **AI-generated output** - all output is AI-generated and should be subject to manual human validation before being relied upon.
>
> **Third-party AI providers** - use of AI agents is subject to the terms of service and privacy policy of the AI provider. These are not controlled by the MCP server or by Evertrust.

## Documentation

| Document                                            | Contents                                                          |
| --------------------------------------------------- | ----------------------------------------------------------------- |
| [Installation](docs/installation.md)                | Install methods, configuration, troubleshooting                   |
| [Authentication](docs/authentication.md)            | Local-account and mTLS modes with environment-variable reference  |
| [Client setup](docs/client-setup.md)                | Claude Desktop, Claude Code, Cursor, Codex, MCP Inspector         |
| [Tool reference](docs/tools-reference.md)           | All 157 tools by domain with safety tiers                         |
| [Knowledge resources](docs/knowledge-resources.md)  | `stream://knowledge/*` catalog and the `search_docs` / `get_doc` tools |
| [Development](docs/development.md)                   | Dev setup, architecture, tests, contributing                      |

## License

Copyright 2026 [Evertrust](https://www.evertrust.fr/). Licensed under the [Apache License 2.0](LICENSE).
