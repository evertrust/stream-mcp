/**
 * whoami: the caller's resolved principal (identity + aggregated permissions +
 * role names). Custom GET /security/principals/self.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

export function registerWhoamiTool(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'whoami',
    {
      description:
        "Return the authenticated caller's resolved principal: identity " +
        '(identifier, optional name, identity provider type/name), aggregated ' +
        'permissions (direct + role permissions, deduped), and role names. Use ' +
        'this to discover who you are and what you can do.\nSafety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const result = await client.get('/api/v1/security/principals/self');
      return text(JSON.stringify(result));
    },
  );
}
