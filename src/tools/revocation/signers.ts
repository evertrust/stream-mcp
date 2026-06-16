/**
 * OCSP signer tools (Revocation domain). Requires the VA (Validation Authority)
 * license module.
 *
 * Routes:
 *   GET    /api/v1/ocsp/signers          -> list (204 -> [])
 *   GET    /api/v1/ocsp/signers/:name    -> single (404 -> OCSP-SIGNER-003)
 *   POST   /api/v1/ocsp/signers          -> create (name unique; cert forced None)
 *   PUT    /api/v1/ocsp/signers          -> update (full-replace, name in body)
 *   DELETE /api/v1/ocsp/signers/:name    -> delete (403 OCSP-SIGNER-005 if a CA references it)
 *   GET    /api/v1/ocsp/signers/:name/csr -> PKCS#10 PEM (application/pkcs10), NOT JSON
 *
 * `assign_ocsp_signer_to_ca` has NO dedicated route: it is a CA update
 * (PUT /api/v1/cas, body-keyed full-replace) that sets enableOCSP:true +
 * ocspSigner:<name> on the CA.
 *
 * Quirks honored:
 *   - certificate is rich-on-read (object) but write-only PEM, and immutable once
 *     set -> in stripFields; never an input field here.
 *   - privateKey.keystore + privateKey.name are immutable once a cert exists; the
 *     server keeps the previous values, so the GET-strip-merge-PUT cycle is safe.
 *   - dn is NOT stripped: it is MANDATORY for a cert-less signer (the server
 *     rejects a missing dn with OCSP-SIGNER-002 "dn is mandatory when certificate
 *     is not specified"), so it must survive the update round-trip. Once a cert
 *     exists the GET omits dn and the server forces it None, so leaving it out of
 *     the strip set is harmless.
 *
 * Grounded in docs/audit/revocation.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
} from '../_scaffold.js';
import { HASH_ALGORITHMS } from './enums.js';

const SIGNER_ROUTE = '/api/v1/ocsp/signers';

// CA resource routes (assign_ocsp_signer_to_ca touches the X509 CA domain).
const CA_GET = (ca: string) => `/api/v1/cas/${encodePathSegment(ca)}`;
const CA_PUT = '/api/v1/cas';
// Server-managed / asymmetric CA fields to strip before the full-replace PUT.
const CA_STRIP_FIELDS = [
  'certificate',
  'privateKey',
  'altPrivateKey',
  'revoked',
  'revocationDate',
  'revocationReason',
  'id',
  'dn',
] as const;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const SIGNER_SPEC: ConfigSpec = {
  noun: 'ocsp_signer',
  nounPlural: 'ocsp_signers',
  label: 'OCSP signer',
  routeCollection: SIGNER_ROUTE,
  routeItem: `${SIGNER_ROUTE}/{name}`,
  idField: 'name',
  immutableKeys: ['name'],
  // certificate: rich-on-read object / write-only PEM, immutable once set ->
  //   must be stripped (server keeps the previous cert; sending the rich object
  //   where a PEM string is expected would 400).
  // id: server-generated (taken from the previous record).
  // dn is NOT stripped: for a cert-less signer `dn` is MANDATORY on the PUT
  //   ("dn is mandatory when certificate is not specified", OCSP-SIGNER-002), so
  //   it must survive the GET-strip-merge-PUT. When a certificate exists the GET
  //   omits `dn` (it's None) and the server forces it to None anyway, so keeping
  //   it out of the strip set is harmless in that case.
  stripFields: ['id', 'certificate'],
  putOnCollection: true,
};

// Shared Zod sub-schemas for the signer's nested objects.
const privateKeyShape = z.object({
  keystore: z.string().describe('Name of an existing keystore.'),
  name: z.string().describe('Private-key alias within the keystore.'),
  hash_algorithm: z
    .enum(HASH_ALGORITHMS)
    .optional()
    .describe(
      'Signing hash algorithm. Omit for EdDSA curves. The server may normalize ' +
        'this to match the certificate.',
    ),
  use_pss: z.boolean().optional().describe('Use RSA-PSS padding.'),
});
type PrivateKeyInput = z.infer<typeof privateKeyShape>;

function mapPrivateKey(pk: PrivateKeyInput): Record<string, unknown> {
  const wire: Record<string, unknown> = {
    keystore: pk.keystore,
    name: pk.name,
  };
  if (pk.hash_algorithm !== undefined)
    wire['hashAlgorithm'] = pk.hash_algorithm;
  if (pk.use_pss !== undefined) wire['usePSS'] = pk.use_pss;
  return wire;
}

function mapTriggers(
  onExpiration: string[] | undefined,
): Record<string, unknown> | undefined {
  if (onExpiration === undefined) return undefined;
  return { onOCSPSignerExpiration: onExpiration };
}

export function registerSignerTools(
  server: McpServer,
  client: StreamClient,
): void {
  // --- list + get -----------------------------------------------------------
  registerReadTools(server, client, SIGNER_SPEC, {
    listDescription:
      'List OCSP signers. Each signer has a name, a privateKey (keystore + alias), ' +
      'an optional certificate (once imported), and optional queue/triggers. ' +
      'Requires the VA license module.',
    getDescription:
      'Get a single OCSP signer by name. Returns the signer with its privateKey, ' +
      'decoded certificate (if imported) or pending dn, queue, and triggers. ' +
      'Requires the VA license module.',
  });

  // --- create ---------------------------------------------------------------
  registerCreateTool(server, client, SIGNER_SPEC, {
    description:
      'Create a new OCSP signer. A fresh signer carries NO certificate (the ' +
      'server forces it to none); you supply a subject `dn` so a CSR can later be ' +
      'generated (generate_ocsp_signer_csr) and the issued certificate imported. ' +
      'The privateKey keystore + alias must already exist. Requires the VA module.',
    mandatoryFields: ['name', 'private_key'],
    inputSchema: z.object({
      name: z
        .string()
        .describe('Unique signer name (immutable primary key). Ask the user.'),
      dn: z
        .string()
        .optional()
        .describe(
          'Subject DN for the future CSR (e.g. "CN=MY-OCSP-SIGNER"). Set this on a ' +
            'fresh signer that has no certificate yet.',
        ),
      private_key: privateKeyShape.describe(
        'Private key reference: { keystore, name, hash_algorithm?, use_pss? }.',
      ),
      queue: z
        .string()
        .optional()
        .describe(
          'Name of an existing queue to attach (validated server-side).',
        ),
      on_expiration_triggers: z
        .array(z.string())
        .optional()
        .describe(
          'Trigger names fired on ON_OCSP_SIGNER_EXPIRATION. Each must reference ' +
            'an existing trigger.',
        ),
    }),
    buildPayload: (args) => {
      const body: Record<string, unknown> = {
        name: args.name,
        privateKey: mapPrivateKey(args.private_key),
      };
      if (args.dn !== undefined) body['dn'] = args.dn;
      if (args.queue !== undefined) body['queue'] = args.queue;
      const triggers = mapTriggers(args.on_expiration_triggers);
      if (triggers !== undefined) body['triggers'] = triggers;
      return body;
    },
  });

  // --- update ---------------------------------------------------------------
  registerUpdateTool(server, client, SIGNER_SPEC, {
    description:
      'Update an OCSP signer (full-replace, keyed by name). NOTE: once the signer ' +
      'has a certificate, its certificate and privateKey keystore/alias are ' +
      'immutable (only hash_algorithm / use_pss are applied) and dn is cleared. ' +
      'Omitted optional fields are reset. Requires the VA module.',
    inputSchema: z.object({
      name: z.string().describe('Signer name to update (lookup key).'),
      dn: z
        .string()
        .optional()
        .describe(
          'Subject DN (only effective while the signer has no certificate).',
        ),
      private_key: privateKeyShape
        .optional()
        .describe(
          'Private key reference. Keystore/alias are ignored once a certificate ' +
            'exists; hash_algorithm / use_pss are always applied.',
        ),
      queue: z.string().optional().describe('Existing queue name to attach.'),
      on_expiration_triggers: z
        .array(z.string())
        .optional()
        .describe('Trigger names for ON_OCSP_SIGNER_EXPIRATION.'),
      clear_fields: z
        .array(z.string())
        .optional()
        .describe(
          'Field names to explicitly null out (e.g. ["queue"]). Cannot target ' +
            'immutable or server-managed fields.',
        ),
    }),
    buildOverrides: (args) => {
      const overrides: Record<string, unknown> = {};
      if (args.dn !== undefined) overrides['dn'] = args.dn;
      if (args.private_key !== undefined) {
        overrides['privateKey'] = mapPrivateKey(args.private_key);
      }
      if (args.queue !== undefined) overrides['queue'] = args.queue;
      const triggers = mapTriggers(args.on_expiration_triggers);
      if (triggers !== undefined) overrides['triggers'] = triggers;
      return overrides;
    },
  });

  // --- delete ---------------------------------------------------------------
  registerDeleteTool(server, client, SIGNER_SPEC, {
    description: 'Delete an OCSP signer by name. Requires the VA module.',
    deleteConstraints:
      'Fails (403 OCSP-SIGNER-005) if any CA still references this signer via ' +
      'its ocspSigner field; clear the reference on the CA first.',
  });

  // --- generate CSR ---------------------------------------------------------
  registerTool(
    server,
    'generate_ocsp_signer_csr',
    {
      description:
        'Generate a PKCS#10 certificate-signing request (CSR) for an OCSP ' +
        "signer, using the signer's dn and privateKey. Returns the CSR as a " +
        'PEM block (-----BEGIN CERTIFICATE REQUEST-----), NOT JSON. Typically ' +
        'called on a signer that has a dn but no certificate yet; the issued ' +
        'certificate is imported afterwards. Requires the VA module.\n' +
        'Safety tier: read-only (no state change)',
      inputSchema: z.object({
        name: z.string().describe('Signer name to generate the CSR for.'),
      }),
    },
    async ({ name }) => {
      // CSR endpoint returns PEM (application/pkcs10), not JSON.
      const pem = await client.getText(
        `${SIGNER_ROUTE}/${encodePathSegment(name)}/csr`,
        'application/pkcs10',
      );
      return text(pem);
    },
  );

  // --- assign signer to CA (CA-resource update; no dedicated route) ----------
  registerTool(
    server,
    'assign_ocsp_signer_to_ca',
    {
      description:
        'Assign an OCSP signer to a CA so the CA serves OCSP responses through ' +
        'it. There is no dedicated route: this updates the CA resource ' +
        '(PUT /api/v1/cas, full-replace keyed by name), setting enableOCSP=true ' +
        'and ocspSigner=<signer name>. The signer must already exist (the server ' +
        'validates the reference). Requires the VA module on the CA.\n' +
        'Safety tier: mutating-safe (idempotent: converges the CA to the assignment)',
      inputSchema: z.object({
        ca: z.string().describe('CA name to assign the OCSP signer to.'),
        ocsp_signer: z
          .string()
          .describe('Name of an existing OCSP signer to bind to the CA.'),
      }),
    },
    async ({ ca, ocsp_signer }) => {
      const result = await getStripMergePutExplicit(
        client,
        CA_GET(ca),
        CA_PUT,
        CA_STRIP_FIELDS,
        { enableOCSP: true, ocspSigner: ocsp_signer },
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'ca',
          name: ca,
          data: result,
          warnings: [
            `OCSP signer '${ocsp_signer}' assigned; enableOCSP set true.`,
          ],
        }),
      );
    },
  );
}
