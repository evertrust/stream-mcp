/**
 * System domain registration: configuration, proxies, queues, license,
 * dictionaries, and the AsciiDoc configuration export.
 *
 * Audit contract: docs/audit/system.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerSystemConfigurationTools } from './configuration.js';
import { registerSystemInfoTools } from './info.js';
import { registerProxyTools } from './proxies.js';
import { registerQueueTools } from './queues.js';

export function registerSystemTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerSystemConfigurationTools(server, client);
  registerProxyTools(server, client);
  registerQueueTools(server, client);
  registerSystemInfoTools(server, client);
}
