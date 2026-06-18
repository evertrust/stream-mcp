/**
 * CRL information tools (Revocation domain).
 *
 * Routes:
 *   GET  /api/v1/crls        -> list CRLInfo (204 -> [])
 *   GET  /api/v1/crls/:ca    -> single CRLInfo (404 -> CA-003)
 *   PUT  /api/v1/crls/:ca    -> update only `nextRefresh` (must be a FUTURE ISO instant)
 *
 * The PUT is NOT a full-replace: the body carries exactly `{ nextRefresh }`,
 * keyed by the `:ca` path param. Everything else on a CRLInfo is system-managed.
 * Server quirk: a past/now `nextRefresh` is accepted (200) but ignored (no-op).
 *
 * Grounded in docs/audit/revocation.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  buildListResponse,
  buildMutateResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';

const ROUTE_COLLECTION = '/api/v1/crls';
// Public distribution endpoints (root-mounted, NOT under /api/v1): the actual
// published CRL bytes and the AIA-served issuer certificate.
const PUBLISHED_CRL_ROUTE = '/crls';
const PUBLISHED_AIA_ROUTE = '/aias';
const MAX_LIST_ITEMS = 50;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

export function registerCrlTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'list_crls',
    {
      description:
        'List CRL (Certificate Revocation List) information for every CA, one ' +
        'entry per CA, sorted by CA name. Each entry reports the CRL number, ' +
        'thisUpdate/nextUpdate, the scheduled nextRefresh, the revoked-entry ' +
        'count (size), and the CA type (managed/external).\nSafety tier: read-only',
      inputSchema: z.object({
        max_items: z
          .number()
          .int()
          .positive()
          .max(100)
          .default(MAX_LIST_ITEMS)
          .describe('Maximum items to return (default 50).'),
        ca_contains: z
          .string()
          .optional()
          .describe('Case-insensitive substring filter on the CA name.'),
      }),
    },
    async ({ max_items, ca_contains }) => {
      // 204 (empty OR forbidden) -> [] via getList.
      const items =
        await client.getList<Record<string, unknown>>(ROUTE_COLLECTION);
      const needle = ca_contains?.toLowerCase();
      const filtered = items.filter((item) => {
        if (!needle) return true;
        const v = item['ca'];
        return typeof v === 'string' && v.toLowerCase().includes(needle);
      });
      return text(buildListResponse(filtered, max_items, 'crl'));
    },
  );

  registerTool(
    server,
    'get_crl',
    {
      description:
        'Get the CRL information for a single CA by its name. Returns the CRL ' +
        'number, thisUpdate/nextUpdate, nextRefresh, revoked-entry count, and ' +
        'CA type. 404 (CA-003) if no CRL information exists for that CA.' +
        '\nSafety tier: read-only',
      inputSchema: z.object({
        ca: z.string().describe('Exact CA name (the CRL lookup key).'),
      }),
    },
    async ({ ca }) => {
      const result = await client.get(
        `${ROUTE_COLLECTION}/${encodePathSegment(ca)}`,
      );
      return text(JSON.stringify(result));
    },
  );

  // get_published_crl: fetch the ACTUAL published CRL bytes from the public
  // distribution endpoint (GET /crls/:ca), unlike get_crl which returns only
  // metadata. Lets an agent close a "generate then verify/decode the CRL" loop.
  registerTool(
    server,
    'get_published_crl',
    {
      description:
        "Fetch a CA's PUBLISHED CRL from Stream's public distribution endpoint " +
        '(GET /crls/:ca). Returns the actual artifact (unlike get_crl, which ' +
        'returns only metadata): PEM text by default, or base64-encoded DER when ' +
        'form="DER". This endpoint is unauthenticated/public. Feed the PEM into ' +
        'decode_crl to inspect entries.\nSafety tier: read-only',
      inputSchema: z.object({
        ca: z.string().describe('CA name (the CRL distribution-point key).'),
        form: z
          .enum(['PEM', 'DER'])
          .default('PEM')
          .describe('PEM text (default) or base64-encoded DER.'),
      }),
    },
    async ({ ca, form }) => {
      const path = `${PUBLISHED_CRL_ROUTE}/${encodePathSegment(ca)}?form=${form}`;
      if (form === 'DER') {
        const buf = await client.getBytes(path, client.exportTimeout);
        return text(
          JSON.stringify({
            ca,
            form,
            base64: Buffer.from(buf).toString('base64'),
          }),
        );
      }
      const pem = await client.getText(
        path,
        'application/x-pem-file',
        client.exportTimeout,
      );
      return text(JSON.stringify({ ca, form, pem }));
    },
  );

  // get_published_aia: the issuer CA certificate served at the AIA endpoint.
  registerTool(
    server,
    'get_published_aia',
    {
      description:
        "Fetch a CA's issuer certificate from its AIA (Authority Information " +
        'Access) distribution endpoint (GET /aias/:ca), returned as base64-' +
        'encoded DER. Unauthenticated/public endpoint. Decode with decode_x509.' +
        '\nSafety tier: read-only',
      inputSchema: z.object({
        ca: z.string().describe('CA name (the AIA distribution-point key).'),
      }),
    },
    async ({ ca }) => {
      const buf = await client.getBytes(
        `${PUBLISHED_AIA_ROUTE}/${encodePathSegment(ca)}`,
        client.exportTimeout,
      );
      return text(
        JSON.stringify({ ca, base64: Buffer.from(buf).toString('base64') }),
      );
    },
  );

  registerTool(
    server,
    'update_crl_next_refresh',
    {
      description:
        "Reschedule a CA's next CRL refresh/regeneration time. This is the ONLY " +
        'mutable field of a CRL information record via the API; everything else ' +
        '(number, thisUpdate, nextUpdate, size, type) is system-managed.\n' +
        'MANDATORY: ca (the CRL/CA lookup key) and next_refresh. Ask the user for ' +
        'both; do not infer or invent them.\n' +
        'IMPORTANT: next_refresh must be a valid ISO-8601 instant STRICTLY in ' +
        'the future. The server silently ignores a past/now value (returns 200 ' +
        'with the record UNCHANGED), so always pass a future timestamp.\n' +
        'Safety tier: mutating-safe',
      inputSchema: z.object({
        ca: z
          .string()
          .describe(
            'REQUIRED. Exact CA name whose CRL refresh to reschedule (lookup key).',
          ),
        next_refresh: z
          .string()
          .describe(
            'REQUIRED. New next-refresh time as an ISO-8601 instant (e.g. ' +
              '"2026-12-31T00:00:00Z"). Must be strictly in the future to take effect.',
          ),
      }),
    },
    async ({ ca, next_refresh }) => {
      const ts = Date.parse(next_refresh);
      if (Number.isNaN(ts)) {
        throw new StreamError(422, {
          errorCode: 'CRL-INVALID-INSTANT',
          message: `next_refresh='${next_refresh}' is not a valid ISO-8601 instant.`,
          remediation:
            'Pass an ISO-8601 timestamp such as "2026-12-31T00:00:00Z".',
        });
      }
      if (ts <= Date.now()) {
        throw new StreamError(422, {
          errorCode: 'CRL-PAST-INSTANT',
          message: `next_refresh='${next_refresh}' is not in the future; the server would ignore it (no-op).`,
          remediation: 'Pass a timestamp strictly later than now.',
        });
      }
      const result = await client.put<Record<string, unknown>>(
        `${ROUTE_COLLECTION}/${encodePathSegment(ca)}`,
        { nextRefresh: next_refresh },
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'crl',
          name: ca,
          data: result,
        }),
      );
    },
  );
}
