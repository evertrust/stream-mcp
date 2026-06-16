/**
 * SSH certificate query tools: search, aggregate, get-by-id.
 * Endpoints: POST /ssh/certificates/search, POST /ssh/certificates/aggregate,
 * GET /ssh/certificates/:id.
 *
 * Notes:
 *  - serial is a STRING on the wire (stored as Long, written as string).
 *  - SCQL (SSH dialect): an empty query is invalid (STREAMQL-001), so the shared
 *    buildSearchPayload defaults it to `id exists`.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  buildSearchPayload,
  buildSearchResponse,
  encodePathSegment,
  SEARCH_RESPONSE_OUTPUT_SCHEMA,
} from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';

import {
  SSH_GROUP_BY_ELEMENTS,
  SSH_HAVING_OPERATORS,
  SSH_SEARCH_FIELDS,
  SSH_SORT_ORDERS,
} from './enums.js';

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// Stream's SortOrder is an enumeratum PlayEnum whose JSON Reads are
// CASE-SENSITIVE and match the exact entryNames (Asc/Desc/KeyAsc/KeyDesc).
// The shared buildSearchPayload/buildSortedBy helper emits uppercase ASC/DESC,
// which the server rejects (400 SSH-CERT-002 "error.expected.validenumvalue" —
// verified live). We therefore build sortedBy here with the correct casing and
// bypass the helper's sort path. Accepts the canonical enum names plus the
// friendly asc/desc aliases.
const SORT_ORDER_ALIASES: Record<string, string> = {
  asc: 'Asc',
  desc: 'Desc',
  keyasc: 'KeyAsc',
  keydesc: 'KeyDesc',
};

function buildSortedByElement(
  sortedBy?: string,
): Array<{ element: string; order: string }> | undefined {
  if (!sortedBy) return undefined;
  const [rawElement, rawOrder] = sortedBy.split(':', 2);
  const element = (rawElement ?? '').trim();
  if (!element) return undefined;
  const orderKey = (rawOrder ?? 'asc').trim().toLowerCase();
  const order = SORT_ORDER_ALIASES[orderKey] ?? 'Asc';
  return [{ element, order }];
}

// ---------------------------------------------------------------------------
// search_ssh_certificates
// ---------------------------------------------------------------------------

const SEARCH_INPUT = z.object({
  query: z
    .string()
    .optional()
    .describe(
      'SCQL (SSH dialect) filter, e.g. `status is valid`, ' +
        '`ca equals "sma-rsa"`, `type equals "USER"`. Empty/omitted defaults ' +
        'to `id exists` (matches all). String fields: ca, serial, ' +
        'publickeythumbprint, template, type, principals, keyid. Date fields: ' +
        'valid.from, valid.until, revocation.date. status is/in ' +
        '[valid,revoked,expired].',
    ),
  fields: z
    .array(z.enum(SSH_SEARCH_FIELDS))
    .optional()
    .describe(
      'Projection of result fields. Omit for the full projection. Valid: ' +
        SSH_SEARCH_FIELDS.join(', ') +
        '.',
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
    .string()
    .optional()
    .describe(
      'Sort as `field:order`, e.g. `validBefore:desc`. Order in ' +
        SSH_SORT_ORDERS.join('/') +
        ' (asc/desc accepted).',
    ),
  with_count: z
    .boolean()
    .optional()
    .describe('When true, the response includes the total count.'),
});

function registerSearch(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'search_ssh_certificates',
    {
      description:
        'Search SSH certificates with the SCQL DSL. Returns a paginated list ' +
        'with each certificate projection (serial is a string). Use ' +
        '`id exists` to match everything.',
      inputSchema: SEARCH_INPUT,
      outputSchema: SEARCH_RESPONSE_OUTPUT_SCHEMA,
    },
    async (args) => {
      const payload = buildSearchPayload({
        query: args.query,
        fields: args.fields as string[] | undefined,
        pageIndex: args.page_index,
        pageSize: args.page_size,
        withCount: args.with_count,
      });
      // Override the shared helper's sort (which emits server-rejected
      // uppercase ASC/DESC) with the correctly-cased SortOrder entryName.
      const sortedBy = buildSortedByElement(args.sorted_by);
      if (sortedBy) payload['sortedBy'] = sortedBy;
      const result = await client.post<Record<string, unknown>>(
        '/api/v1/ssh/certificates/search',
        payload,
      );
      const response = buildSearchResponse(
        result ?? {},
        payload['pageIndex'] as number,
        payload['pageSize'] as number,
      );
      return {
        ...text(JSON.stringify(response)),
        structuredContent: response,
      };
    },
  );
}

// ---------------------------------------------------------------------------
// aggregate_ssh_certificates
// ---------------------------------------------------------------------------

const AGGREGATE_INPUT = z.object({
  query: z
    .string()
    .optional()
    .describe(
      'SCQL filter (same DSL as search). Empty/omitted defaults to ' +
        '`id exists` (matches all).',
    ),
  group_by: z
    .array(z.enum(SSH_GROUP_BY_ELEMENTS))
    .optional()
    .describe(
      'Group-by elements. Omit to aggregate everything into one bucket. ' +
        'Valid: ' +
        SSH_GROUP_BY_ELEMENTS.join(', ') +
        '.',
    ),
  with_count: z
    .boolean()
    .optional()
    .describe('When true, adds the grand total `count` to the response.'),
  sort_order: z
    .enum(SSH_SORT_ORDERS)
    .optional()
    .describe('Sort the aggregation buckets by count.'),
  limit: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe('Maximum number of buckets returned.'),
  having_operator: z
    .enum(SSH_HAVING_OPERATORS)
    .optional()
    .describe(
      'Filter buckets by count using this operator (requires having_value).',
    ),
  having_value: z
    .number()
    .int()
    .optional()
    .describe(
      'Count threshold for the having filter (requires having_operator).',
    ),
});

function registerAggregate(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'aggregate_ssh_certificates',
    {
      description:
        'Aggregate (count/group) SSH certificates by one or more dimensions ' +
        '(e.g. type, status, template, validBefore.month). Returns ' +
        'aggregation buckets `{ _id: {...}, count }`. Null group values bucket ' +
        'as "#empty".',
      inputSchema: AGGREGATE_INPUT,
    },
    async (args) => {
      if (
        (args.having_operator === undefined) !==
        (args.having_value === undefined)
      ) {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message:
            'having_operator and having_value must be provided together.',
          remediation:
            'Pass both having_operator and having_value, or neither.',
        });
      }

      const query = args.query && args.query.trim() ? args.query : 'id exists';
      const payload: Record<string, unknown> = { query };
      if (args.group_by && args.group_by.length > 0) {
        payload['groupBy'] = args.group_by;
      }
      if (args.with_count) payload['withCount'] = true;
      if (args.sort_order) payload['sortOrder'] = args.sort_order;
      if (args.limit !== undefined) payload['limit'] = args.limit;
      if (args.having_operator !== undefined) {
        payload['having'] = {
          operator: args.having_operator,
          value: args.having_value,
        };
      }

      const result = await client.post<Record<string, unknown>>(
        '/api/v1/ssh/certificates/aggregate',
        payload,
      );
      return text(JSON.stringify(result ?? { items: [] }));
    },
  );
}

// ---------------------------------------------------------------------------
// get_ssh_certificate
// ---------------------------------------------------------------------------

const GET_INPUT = z.object({
  id: z.string().describe('The SSH certificate id (24-hex Mongo ObjectId).'),
});

function registerGet(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_ssh_certificate',
    {
      description:
        'Get a single SSH certificate by id. Returns ' +
        '`{ certificate, permissions: { revoke } }`; the certificate `serial` ' +
        'is a string.',
      inputSchema: GET_INPUT,
    },
    async (args) => {
      if (!OBJECT_ID_RE.test(args.id)) {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message: `Invalid SSH certificate id '${args.id}': expected a 24-hex ObjectId.`,
          remediation:
            'Use search_ssh_certificates to find a certificate id, then pass it here.',
        });
      }
      const result = await client.get<Record<string, unknown>>(
        `/api/v1/ssh/certificates/${encodePathSegment(args.id)}`,
      );
      return text(JSON.stringify(result));
    },
  );
}

export function registerSshCertificateQueryTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerSearch(server, client);
  registerAggregate(server, client);
  registerGet(server, client);
}
