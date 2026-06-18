# Security Policy

`@evertrust/stream-mcp` is an MCP server that operates a PKI control plane
(certificate authorities, OCSP/TSA signers, keystores, RBAC). Security issues
are taken seriously.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Please report it privately using GitHub's
[private vulnerability reporting](https://github.com/evertrust/stream-mcp/security/advisories/new)
("Report a vulnerability" under the repository's *Security* tab). If you cannot
use that channel, contact the Evertrust security team through the channels
listed at <https://www.evertrust.io>.

Please include:

- a description of the issue and its impact,
- the affected version(s) and configuration (auth mode, Stream version),
- reproduction steps or a proof of concept.

We aim to acknowledge a report within a few business days and will coordinate a
fix and disclosure timeline with you.

## Scope

This policy covers the MCP server in this repository. Vulnerabilities in the
Evertrust Stream backend itself should be reported through Evertrust's product
security channel.

In-scope examples: secret leakage through tool output or logs, SSRF via outbound
trigger URLs, path traversal in API routing, TLS-verification bypass, or any way
to make the server perform an unintended privileged operation.

## Supported versions

The server targets **Evertrust Stream 2.1**. Only the latest published release
of this package receives security fixes.

## Handling of secrets

The server never logs request headers, bodies, or tool arguments. Private keys,
PKCS#12 material, PINs, and credential secrets are write-only and redacted from
tool output. If you observe secret material reaching tool output or logs, treat
it as a security issue and report it privately.
