/**
 * Audit event query tools: search, get-by-id, and the search dictionary.
 * Endpoints:
 *   - POST /events/search            -> paginated EventSearchResults
 *   - GET  /events/:id               -> single Event
 *   - GET  /events/search/dictionary -> { modules, codes, details }
 *
 * Audit contract: docs/audit/events.md.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  buildSearchResponse,
  buildSortedBy,
  encodePathSegment,
  MAX_PAGE_SIZE,
  SEARCH_RESPONSE_OUTPUT_SCHEMA,
} from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';
import { EVENT_SORT_FIELDS } from './enums.js';

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// ---------------------------------------------------------------------------
// search_events
// ---------------------------------------------------------------------------

// SortOrder wire values are case-sensitive: Asc/KeyAsc => +1, Desc/KeyDesc => -1.
const SORT_ORDERS = ['Asc', 'Desc', 'KeyAsc', 'KeyDesc'] as const;

const SORT_ELEMENT = z.object({
  element: z
    .enum(EVENT_SORT_FIELDS)
    .describe('Sortable field. One of: ' + EVENT_SORT_FIELDS.join(', ') + '.'),
  order: z
    .enum(SORT_ORDERS)
    .describe(
      'Sort order (case-sensitive). Asc/KeyAsc ascending, Desc/KeyDesc descending.',
    ),
});

const SEARCH_INPUT = z.object({
  query: z
    .string()
    .optional()
    .describe(
      'SEQL filter expression. Empty/omitted matches all events (the server ' +
        'applies an empty filter). String fields: code, node, module, status ' +
        '(equals/matches/contains/in). Date field: timestamp (equals/before/' +
        'after, e.g. `timestamp after -7days`). Detail fields: `detail.<key>` ' +
        '(use get_event_dictionary for valid keys), with exists/within too. ' +
        'Note: `exists` is only valid on `detail.<key>`, not on id/code/etc. ' +
        'Example: `module equals service and status equals success`.',
    ),
  page_index: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe('1-based page index (default 1).'),
  page_size: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe('Page size (default 20, capped at 100).'),
  sorted_by: z
    .union([z.string(), z.array(SORT_ELEMENT)])
    .optional()
    .describe(
      'Sort as `field:order` (e.g. `timestamp:desc`) or as a list of ' +
        '{ element, order } entries. Sortable elements: ' +
        EVENT_SORT_FIELDS.join(', ') +
        '. Duplicate elements are rejected by the server.',
    ),
  with_count: z
    .boolean()
    .optional()
    .describe('When true, the response includes the total matching count.'),
});

function registerSearch(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'search_events',
    {
      description:
        'Search audit events with the SEQL DSL. Returns a paginated page of ' +
        'events (id, code, module, node, timestamp, status, details). Events ' +
        'are immutable/append-only. Omit `query` to match every event.',
      inputSchema: SEARCH_INPUT,
      outputSchema: SEARCH_RESPONSE_OUTPUT_SCHEMA,
    },
    async (args) => {
      const pageIndex =
        args.page_index && args.page_index > 0 ? args.page_index : 1;
      const pageSize = Math.min(args.page_size ?? 20, MAX_PAGE_SIZE);
      const payload: Record<string, unknown> = {
        pageIndex,
        pageSize,
      };
      // SEQL has no match-all literal for events (`exists` is detail-only, so
      // `id exists` is a STREAMQL-001 parse error). An absent `query` makes the
      // server apply an empty filter (match all), per the audit contract.
      if (args.query && args.query.trim()) payload['query'] = args.query;
      const sortedBy = buildSortedBy(args.sorted_by);
      if (sortedBy) payload['sortedBy'] = sortedBy;
      if (args.with_count) payload['withCount'] = true;

      const result = await client.post<Record<string, unknown>>(
        '/api/v1/events/search',
        payload,
      );
      const response = buildSearchResponse(result ?? {}, pageIndex, pageSize);
      return {
        ...text(JSON.stringify(response)),
        structuredContent: response,
      };
    },
  );
}

// ---------------------------------------------------------------------------
// get_event
// ---------------------------------------------------------------------------

const GET_INPUT = z.object({
  id: z.string().describe('The event id (24-hex Mongo ObjectId).'),
});

function registerGet(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_event',
    {
      description:
        'Get a single audit event by id, including its details and the ' +
        'server-generated tamper-evidence seal (when chainsign is enabled).',
      inputSchema: GET_INPUT,
    },
    async (args) => {
      if (!OBJECT_ID_RE.test(args.id)) {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message: `Invalid event id '${args.id}': expected a 24-hex ObjectId.`,
          remediation:
            'Use search_events to find an event id, then pass it here.',
        });
      }
      const result = await client.get<Record<string, unknown>>(
        `/api/v1/events/${encodePathSegment(args.id)}`,
      );
      return text(JSON.stringify(result));
    },
  );
}

// ---------------------------------------------------------------------------
// get_event_dictionary
// ---------------------------------------------------------------------------

function registerDictionary(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_event_dictionary',
    {
      description:
        'Get the searchable audit-event vocabulary: all event `modules`, all ' +
        'event `codes`, and all `details` keys. Use this to know which ' +
        'code/module/status/detail.<key> literals are valid in a SEQL query. ' +
        'Includes deprecated codes/modules present on historical events.',
      inputSchema: z.object({}),
    },
    async () => {
      const result = await client.get<Record<string, unknown>>(
        '/api/v1/events/search/dictionary',
      );
      return text(JSON.stringify(result));
    },
  );
}

export function registerEventQueryTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerSearch(server, client);
  registerGet(server, client);
  registerDictionary(server, client);
}
