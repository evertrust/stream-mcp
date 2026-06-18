# Contributing

Thanks for contributing to `@evertrust/stream-mcp`.

## Prerequisites

- [Bun](https://bun.sh/) 1.x (the project's package manager and test runner) or
  Node.js >= 22.19.
- Access to an Evertrust Stream 2.1 instance for the optional live/E2E tiers.

See [docs/development.md](docs/development.md) for the full development guide
(architecture, the route-truth check, and the test tiers).

## Workflow

1. Branch off `main`.
2. Make your change with a test. The project uses test-driven development; new
   behavior needs unit tests and, where it touches the wire contract, a note in
   `docs/audit/<domain>.md`.
3. Run the full local gate before opening a PR:

   ```bash
   bun run validate:ci
   ```

   This runs format, lint, typecheck, build, the API route-truth check, the unit
   suite, and the deterministic scenario suite.
4. Open a PR. CI re-runs the gate and (when QA secrets are available) a read-only
   E2E smoke test.

## Conventional commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`, `perf:`).
Releases are automated by semantic-release from the commit history, so the type
and scope matter.

## Code style

- TypeScript, ESM, strict mode. Prefer many small, focused modules.
- Immutable data: return new objects rather than mutating inputs.
- Never log or return secret material; route reads that may carry secrets through
  the redaction helpers.
- Every interpolated path segment must be URL-encoded (`encodePathSegment`).

## Security

Please report vulnerabilities privately - see [SECURITY.md](SECURITY.md).
