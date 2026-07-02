/**
 * Read-only system info tools: license, dictionaries, and the AsciiDoc export.
 *
 * Audit: docs/audit/system.md sections 14-19.
 *   - GET /licenses          -> LicenseInfo object
 *   - GET /licenses/modules  -> string[] of entitled module entryNames (204 -> [])
 *   - GET /dictionaries/keys -> [{ name, pqc, type }]
 *   - GET /dictionaries/dns  -> string[]
 *   - GET /dictionaries/sans -> string[]
 *   - GET /adoc?withTrustChains -> text/plain AsciiDoc (via getText, NOT JSON)
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// export_configuration output budget: the AsciiDoc export of a populated
// instance can approach the 10 MiB transport cap, which would flood the model
// context in one call. Cap per call and let the caller page with `offset`.
const EXPORT_DEFAULT_MAX_CHARS = 60_000;
const EXPORT_MAX_MAX_CHARS = 200_000;

export function registerSystemInfoTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'get_license_info',
    {
      description:
        'Get Stream license information: validity, expiration, build version/time, entitled modules (sorted), libraries, and release channel.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const result = await client.get('/api/v1/licenses');
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'get_license_modules',
    {
      description:
        'Get the list of entitled Stream module entryNames (e.g. stream-ca, stream-va, stream-tsa, stream-ssh) in declaration order. No permission required. Empty list if none entitled.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const modules = await client.getList<string>('/api/v1/licenses/modules');
      return text(JSON.stringify({ modules, count: modules.length }));
    },
  );

  registerTool(
    server,
    'get_key_types',
    {
      description:
        'Get the supported asymmetric key types (CFAsymmetricAlgorithm) as objects { name, pqc, type }. The set is license/version-dependent — always read it live rather than assuming.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const keys = await client.getList<Record<string, unknown>>(
        '/api/v1/dictionaries/keys',
      );
      return text(JSON.stringify({ keyTypes: keys, count: keys.length }));
    },
  );

  registerTool(
    server,
    'get_dn_elements',
    {
      description:
        'Get the supported Distinguished Name (DN) element names (e.g. CN, OU, O, C, ...) as a string array.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const elements = await client.getList<string>('/api/v1/dictionaries/dns');
      return text(
        JSON.stringify({ dnElements: elements, count: elements.length }),
      );
    },
  );

  registerTool(
    server,
    'get_san_types',
    {
      description:
        'Get the supported Subject Alternative Name (SAN) type names (e.g. DNSNAME, RFC822NAME, IPADDRESS, URI, ...) as a string array.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const sans = await client.getList<string>('/api/v1/dictionaries/sans');
      return text(JSON.stringify({ sanTypes: sans, count: sans.length }));
    },
  );

  registerTool(
    server,
    'export_configuration',
    {
      description:
        'Export the full Stream configuration as an AsciiDoc ("adoc") cookbook document (text/plain, NOT JSON). ' +
        'Optionally include CA trust-chain diagrams. Only sections you can AUDIT are included; if you can audit nothing the body is empty.\n' +
        `Output is capped at max_chars (default ${EXPORT_DEFAULT_MAX_CHARS}) per call; a truncation marker gives the offset to pass for the next chunk.\n` +
        'Safety tier: read-only',
      inputSchema: z.object({
        with_trust_chains: z
          .boolean()
          .optional()
          .describe(
            'When true, prepend a Trust Chains section with Graphviz/DOT digraphs of CA trust chains. Default false.',
          ),
        offset: z
          .number()
          .int()
          .min(0)
          .default(0)
          .describe(
            'Character offset to continue a previous, truncated export from.',
          ),
        max_chars: z
          .number()
          .int()
          .min(1)
          .max(EXPORT_MAX_MAX_CHARS)
          .default(EXPORT_DEFAULT_MAX_CHARS)
          .describe(
            `Maximum characters returned per call (default ${EXPORT_DEFAULT_MAX_CHARS}, ` +
              `max ${EXPORT_MAX_MAX_CHARS}).`,
          ),
      }),
    },
    async ({ with_trust_chains, offset, max_chars }) => {
      // Defensive defaults: schema defaults only apply via SDK-side parsing.
      const start = offset ?? 0;
      const cap = max_chars ?? EXPORT_DEFAULT_MAX_CHARS;
      const path = with_trust_chains
        ? '/api/v1/adoc?withTrustChains=true'
        : '/api/v1/adoc';
      // Full-config export can be large/slow — use the longer export timeout.
      const adoc = await client.getText(
        path,
        'text/plain',
        client.exportTimeout,
      );
      const total = adoc.length;
      if (start >= total && total > 0) {
        return text(
          `<offset ${start} is beyond the document end (${total} chars). ` +
            'Restart with offset=0.>',
        );
      }
      const end = Math.min(start + cap, total);
      const slice = adoc.slice(start, end);
      if (end < total) {
        return text(
          `${slice}\n\n<truncated: showing chars ${start}-${end} of ${total}. ` +
            `Call export_configuration again with offset=${end} for the next chunk.>`,
        );
      }
      return text(slice);
    },
  );
}
