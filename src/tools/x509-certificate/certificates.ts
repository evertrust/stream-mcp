/**
 * X509 certificate query tools: search, aggregate, get-by-id.
 * Endpoints: POST /certificates/search, POST /certificates/aggregate,
 * GET /certificates/:id.
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
  GROUP_BY_ELEMENTS,
  HAVING_OPERATORS,
  SEARCH_FIELDS,
  SORT_ORDERS,
} from './enums.js';

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// ---------------------------------------------------------------------------
// search_certificates
// ---------------------------------------------------------------------------

const SEARCH_INPUT = z.object({
  query: z
    .string()
    .optional()
    .describe(
      'SCQL filter, e.g. `status is valid`, `dn contains example.com`, ' +
        '`valid.until before 30 days`. Empty/omitted defaults to `id exists` ' +
        '(matches all). String fields: ca, dn, issuer, serial, ' +
        'publickeythumbprint, template. Date fields: valid.from, valid.until, ' +
        'revocation.date. status in [valid,expired,revoked].',
    ),
  fields: z
    .array(z.enum(SEARCH_FIELDS))
    .optional()
    .describe(
      'Projection of result fields. Omit to get the full object. Valid: ' +
        SEARCH_FIELDS.join(', ') +
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
    .union([
      z.string(),
      z.array(z.object({ element: z.string(), order: z.string() })),
    ])
    .optional()
    .describe(
      'Sort as `field:order` (e.g. `notAfter:desc`) or as a list of ' +
        '{ element, order } entries. Order in ' +
        SORT_ORDERS.join('/') +
        ' (case-insensitive).',
    ),
  with_count: z
    .boolean()
    .optional()
    .describe('When true, the response includes the total count.'),
});

function registerSearch(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'search_certificates',
    {
      description:
        'Search X509 certificates with the SCQL DSL. Returns a paginated list ' +
        'with each certificate projection. Use `id exists` to match everything.',
      inputSchema: SEARCH_INPUT,
      outputSchema: SEARCH_RESPONSE_OUTPUT_SCHEMA,
    },
    async (args) => {
      const payload = buildSearchPayload({
        query: args.query,
        fields: args.fields as string[] | undefined,
        pageIndex: args.page_index,
        pageSize: args.page_size,
        sortedBy: args.sorted_by,
        withCount: args.with_count,
      });
      const result = await client.post<Record<string, unknown>>(
        '/api/v1/certificates/search',
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
// aggregate_certificates
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
    .array(z.enum(GROUP_BY_ELEMENTS))
    .optional()
    .describe(
      'Group-by elements. Omit to aggregate everything into one bucket. ' +
        'Valid: ' +
        GROUP_BY_ELEMENTS.join(', ') +
        '.',
    ),
  with_count: z
    .boolean()
    .optional()
    .describe('When true, adds the grand total `count` to the response.'),
  sort_order: z
    .enum(SORT_ORDERS)
    .optional()
    .describe('Sort the aggregation buckets by count.'),
  limit: z
    .number()
    .int()
    .min(1)
    .optional()
    .describe('Maximum number of buckets returned.'),
  having_operator: z
    .enum(HAVING_OPERATORS)
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
    'aggregate_certificates',
    {
      description:
        'Aggregate (count/group) X509 certificates by one or more dimensions ' +
        '(e.g. status, template, notAfter.month). Returns Mongo aggregation ' +
        'buckets `{ _id: {...}, count }`.',
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
        '/api/v1/certificates/aggregate',
        payload,
      );
      return text(JSON.stringify(result ?? { items: [] }));
    },
  );
}

// ---------------------------------------------------------------------------
// get_certificate
// ---------------------------------------------------------------------------

const GET_INPUT = z.object({
  id: z.string().describe('The certificate id (24-hex Mongo ObjectId).'),
});

function registerGet(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_certificate',
    {
      description:
        'Get a single X509 certificate by id, including its PEM and the ' +
        "caller's revoke permission (`permissions.revoke`).",
      inputSchema: GET_INPUT,
    },
    async (args) => {
      if (!OBJECT_ID_RE.test(args.id)) {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message: `Invalid certificate id '${args.id}': expected a 24-hex ObjectId.`,
          remediation:
            'Use search_certificates to find a certificate id, then pass it here.',
        });
      }
      const result = await client.get<Record<string, unknown>>(
        `/api/v1/certificates/${encodePathSegment(args.id)}`,
      );
      return text(JSON.stringify(result));
    },
  );
}

export function registerCertificateQueryTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerSearch(server, client);
  registerAggregate(server, client);
  registerGet(server, client);
}
