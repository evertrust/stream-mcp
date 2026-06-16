/**
 * Trust-chain tools:
 *   - get_trust_chain: build the chain for an arbitrary certificate against
 *     Stream's configured CAs (POST /api/v1/rfc5280/tc?order=, multipart `x509`).
 *     Reuses the x509 multipart field. Only issuers known to Stream's truststore
 *     are resolved (an unrelated public leaf returns just itself).
 *   - list_trust_chains: GET /api/v1/trustchains -> array of anchors (204 -> []).
 *   - get_trust_chain_for_anchor: GET /api/v1/trustchains/:anchor where :anchor
 *     is the CA name (the immutable key).
 *
 * Audit: docs/audit/utilities.md (RFC5280 /tc + TrustChains endpoints).
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { buildListResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import { TRUST_CHAIN_ORDERS } from './enums.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const MAX_ANCHORS = 100;

export function registerTrustChainTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'get_trust_chain',
    {
      description:
        'Build the trust chain for a given certificate using the CAs configured in ' +
        "Stream's trust manager. Returns a JSON array of decoded X.509 objects " +
        '(leaf/root ordering per `order`). Only issuers known to Stream resolve — ' +
        'a certificate whose issuer is not a configured CA returns just itself.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        content: z
          .string()
          .min(1)
          .describe(
            'The certificate content: a PEM string or base64 DER. Uploaded as a ' +
              'multipart file.',
          ),
        order: z
          .enum(TRUST_CHAIN_ORDERS)
          .optional()
          .describe(
            'Chain ordering: ltr (leaf->root, default), rtl (root->leaf), ' +
              'irtl (issuing root->leaf), iltr (issuing leaf->root).',
          ),
      }),
    },
    async ({ content, order }) => {
      const path = order
        ? `/api/v1/rfc5280/tc?order=${encodeURIComponent(order)}`
        : '/api/v1/rfc5280/tc';
      const result = await client.postMultipart(
        path,
        [
          {
            fieldName: 'x509',
            filename: 'cert.pem',
            mimeType: 'application/octet-stream',
            data: content,
          },
        ],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'list_trust_chains',
    {
      description:
        'List all trust chains built from the configured Certificate Authorities ' +
        '(those that have a certificate). Returns top-level anchors, each with a ' +
        'recursive `subordinates` array. Returns an empty list if there are no CAs ' +
        'with certificates or you lack CA audit permission.\nSafety tier: read-only',
      inputSchema: z.object({
        max_items: z
          .number()
          .int()
          .positive()
          .max(MAX_ANCHORS)
          .default(MAX_ANCHORS)
          .describe('Maximum top-level anchors to return (default 100).'),
      }),
    },
    async ({ max_items }) => {
      const anchors = await client.getList<Record<string, unknown>>(
        '/api/v1/trustchains',
      );
      return text(buildListResponse(anchors, max_items, 'trust_chain'));
    },
  );

  registerTool(
    server,
    'get_trust_chain_for_anchor',
    {
      description:
        'Get the single trust chain rooted at the CA whose name equals the given ' +
        'anchor. The anchor is the CA name (the immutable key), NOT its id. Returns ' +
        'the named CA plus its recursive subordinates.\nSafety tier: read-only',
      inputSchema: z.object({
        anchor: z
          .string()
          .min(1)
          .describe(
            'The CA name (immutable key) to use as the trust-chain root.',
          ),
      }),
    },
    async ({ anchor }) => {
      const result = await client.get(
        `/api/v1/trustchains/${encodePathSegment(anchor)}`,
      );
      return text(JSON.stringify(result));
    },
  );
}
