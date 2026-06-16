import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../client/http.js';

/**
 * Central tool-registration entry point. Each domain exports a
 * `registerXxxTools(server, client)` from `src/tools/<domain>/index.ts`; they
 * are wired in here during the integration step. Kept as the single edit point
 * so parallel domain work never conflicts on `src/index.ts`.
 */
export function registerAllTools(
  _server: McpServer,
  _client: StreamClient,
): void {
  // Domain registrations are wired here at integration:
  //   registerX509CaTools(_server, _client);
  //   registerX509CertificateTools(_server, _client);
  //   ...
}
