/**
 * Events domain registration: audit-event search/get/dictionary and the
 * chain-integrity verification tools.
 *
 * Audit contract: docs/audit/events.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerEventIntegrityTools } from './integrity.js';
import { registerEventQueryTools } from './search.js';

export function registerEventTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerEventQueryTools(server, client);
  registerEventIntegrityTools(server, client);
}
