/**
 * SSH KRL (Key Revocation List) tools: generate_krl, list_krls, get_krl.
 * Endpoints:
 *  - GET /ssh/cas/:name/krl (?lazy)  -> 204 fire-and-forget (generate)
 *  - GET /ssh/krls                   -> list KRL info (204 -> [])
 *  - GET /ssh/krls/:ca               -> KRL info for one CA (404 SSH-CA-003 if none)
 *
 * generate_krl only requests asynchronous generation; the KRL artifact is
 * produced in the background. Poll get_krl for the resulting status.
 */
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import { buildListResponse, encodePathSegment } from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// ---------------------------------------------------------------------------
// generate_krl
// ---------------------------------------------------------------------------

const GENERATE_INPUT = z.object({
  name: z.string().min(1).describe('SSH CA name to (re)generate the KRL for.'),
  lazy: z
    .boolean()
    .optional()
    .describe('When true, requests a lazy (incremental) regeneration.'),
});

function registerGenerate(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'generate_krl',
    {
      description:
        'Request asynchronous KRL generation for an SSH CA (fire-and-forget; ' +
        'returns 204 with no KRL body). The CA must be ready (have a ' +
        'publicKey) else SSH-CA-006. Poll get_krl for the resulting status.',
      inputSchema: GENERATE_INPUT,
    },
    async (args) => {
      const params = args.lazy
        ? new URLSearchParams({ lazy: 'true' })
        : undefined;
      await client.get(
        `/api/v1/ssh/cas/${encodePathSegment(args.name)}/krl`,
        params,
      );
      return text(
        JSON.stringify({
          status: 'requested',
          kind: 'krl',
          ca: args.name,
          lazy: args.lazy ?? false,
          note: 'KRL generation is asynchronous; poll get_krl for the result.',
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// list_krls
// ---------------------------------------------------------------------------

const LIST_INPUT = z.object({
  max_items: z
    .number()
    .int()
    .positive()
    .max(100)
    .default(50)
    .describe('Maximum items to return (default 50).'),
});

function registerList(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'list_krls',
    {
      description:
        'List KRL info (metadata/status) across SSH CAs. Each entry has ' +
        '{ ca, number?, thisUpdate?, nextRefresh?, error? }. This is KRL ' +
        'status, not the KRL artifact. Empty/forbidden returns [].',
      inputSchema: LIST_INPUT,
    },
    async (args) => {
      const items =
        await client.getList<Record<string, unknown>>('/api/v1/ssh/krls');
      return text(buildListResponse(items, args.max_items, 'krl'));
    },
  );
}

// ---------------------------------------------------------------------------
// get_krl
// ---------------------------------------------------------------------------

const GET_INPUT = z.object({
  ca: z.string().min(1).describe('SSH CA name to fetch KRL info for.'),
});

function registerGet(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_krl',
    {
      description:
        'Get KRL info (status) for one SSH CA. Returns ' +
        '{ ca, number?, thisUpdate?, nextRefresh?, error? }. Returns 404 ' +
        'SSH-CA-003 if the CA has never generated a KRL (even if the CA itself ' +
        'exists).',
      inputSchema: GET_INPUT,
    },
    async (args) => {
      const result = await client.get<Record<string, unknown>>(
        `/api/v1/ssh/krls/${encodePathSegment(args.ca)}`,
      );
      return text(JSON.stringify(result));
    },
  );
}

export function registerSshKrlTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerGenerate(server, client);
  registerList(server, client);
  registerGet(server, client);
}
