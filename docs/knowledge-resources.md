# Knowledge Resources

The server ships an embedded knowledge base so an LLM client can learn how to use
the tools correctly before acting. The content is bundled at build time and
exposed two ways:

1. **MCP resources** at `stream://knowledge/*` URIs (for clients that read MCP
   resources).
2. **Tools** — `search_docs` and `get_doc` — so any client can reach the same
   content without resource support.

## Topics

15 top-level topics are served (priority hints in parentheses):

| URI | Topic |
|-----|-------|
| `stream://knowledge/server-rules` | Operating rules & conventions (read first) |
| `stream://knowledge/tool-selection` | Deterministic "which tool for which task" playbook |
| `stream://knowledge/query-languages` | SCQL (certificates) and SEQL (events) syntax |
| `stream://knowledge/architecture` | Modules and object model overview |
| `stream://knowledge/authentication` | Local-account and X.509/mTLS auth |
| `stream://knowledge/ca-management` | Create-from-scratch vs import, issue, CRL |
| `stream://knowledge/lifecycle` | Certificate enrollment & revocation (X509 + SSH) |
| `stream://knowledge/templates` | X509 profiles and SSH templates |
| `stream://knowledge/revocation` | CRL info, OCSP signers, external RL storage |
| `stream://knowledge/keystores` | Keystores, keys, and HSM |
| `stream://knowledge/triggers` | Notification triggers |
| `stream://knowledge/rbac` | Roles, identities, providers, credentials |
| `stream://knowledge/tsa` | Timestamping authorities, signers, NTP |
| `stream://knowledge/ssh` | OpenSSH CAs, templates, certificates, KRLs |
| `stream://knowledge/system-admin` | System config, proxies, queues, license, audit |

### Section resources

Long topics are also split into per-section URIs of the form
`stream://knowledge/<topic>/<section>` (e.g.
`stream://knowledge/query-languages/scql` and `…/ca-management/<section>`). These
are addressable directly but kept out of the default resource listing to keep it
short. A resource **template** (`stream://knowledge/{topic}/{section}`) advertises
the scheme for clients that prefer completion over enumeration.

## Tools

### `search_docs`

Keyword search across the knowledge base. Returns the best-matching topics with
short snippets and their URIs.

```json
{ "query": "create root CA from scratch", "max_results": 5 }
```

### `get_doc`

Return the full markdown of a topic by URI (or bare slug):

```json
{ "uri": "ca-management" }
// or { "uri": "stream://knowledge/query-languages/scql" }
```

## Query languages

Stream has exactly **two** query DSLs, documented under
`stream://knowledge/query-languages`:

- **SCQL** — Stream Certificates Query Language — used by `search_certificates`,
  `aggregate_certificates`, and `search_ssh_certificates`.
- **SEQL** — Stream Events Query Language — used by `search_events`.

There is no discovery, request-workflow, or permission query language in Stream.
