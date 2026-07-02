/**
 * Timestamping Signer tools. Requires the TSA license module.
 *
 * Routes:
 *   GET    /api/v1/timestamping/signers          -> list (204 -> [])
 *   GET    /api/v1/timestamping/signers/:name    -> single (404 -> TIMESTAMPING-SIGNER-003)
 *   POST   /api/v1/timestamping/signers          -> create (name unique; cert forced None)
 *   PUT    /api/v1/timestamping/signers          -> update (full-replace, name in body)
 *   DELETE /api/v1/timestamping/signers/:name    -> delete (403 TIMESTAMPING-SIGNER-005 if a TSA references it)
 *   GET    /api/v1/timestamping/signers/:name/csr -> PKCS#10 PEM (application/pkcs10), NOT JSON
 *
 * Quirks honored:
 *   - certificate is rich-on-read (object) but write-only PEM; forced None on
 *     create and immutable once set -> in stripFields; never an input field.
 *     The signer certificate must carry the `timeStamping` EKU only, flagged
 *     critical.
 *   - privateKey.keystore + privateKey.name are immutable once a cert exists; the
 *     server keeps the previous values, so the GET-strip-merge-PUT cycle is safe.
 *   - dn is mandatory while the signer has no certificate and is forced None by
 *     the server once a cert exists, so it is NOT stripped: the GET value (or a
 *     user override) is carried through to keep the no-cert PUT valid.
 *
 * Grounded in docs/audit/tsa.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import { encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import {
  type ConfigSpec,
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
} from '../_scaffold.js';
import { HASH_ALGORITHMS } from './enums.js';

const SIGNER_ROUTE = '/api/v1/timestamping/signers';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const SIGNER_SPEC: ConfigSpec = {
  noun: 'tsa_signer',
  nounPlural: 'tsa_signers',
  label: 'timestamping signer',
  routeCollection: SIGNER_ROUTE,
  routeItem: `${SIGNER_ROUTE}/{name}`,
  idField: 'name',
  immutableKeys: ['name'],
  // certificate: rich-on-read object / write-only PEM, forced None on create and
  // immutable once set. id: server-generated. dn is NOT stripped: it is the
  // PEM-less signer's mandatory subject and the server requires it whenever the
  // signer has no certificate (else 400 "dn is mandatory when certificate is not
  // specified"). When a certificate exists the GET returns no dn (server forced
  // it to None), so there is nothing to strip; and on cert-attach the server's
  // updateFrom forces dn=None before validation, so a carried-over dn is harmless.
  stripFields: ['id', 'certificate'],
  putOnCollection: true,
};

// Shared Zod sub-schema for the signer's private key.
const privateKeyShape = z.object({
  keystore: z.string().describe('Name of an existing keystore.'),
  name: z.string().describe('Private-key alias within the keystore.'),
  hash_algorithm: z
    .enum(HASH_ALGORITHMS)
    .optional()
    .describe(
      'Signing hash algorithm. REQUIRED by the server on create for RSA ' +
        'keys (400 "Missing hash algorithm" otherwise - verified live); EC ' +
        'curves may sign without one. The server may normalize this to match ' +
        'the key/certificate.',
    ),
  use_pss: z
    .boolean()
    .optional()
    .describe('Use RSA-PSS padding (only valid for PKCS11 RSA keys).'),
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
  return { onTSASignerExpiration: onExpiration };
}

export function registerSignerTools(
  server: McpServer,
  client: StreamClient,
): void {
  // --- list + get -----------------------------------------------------------
  registerReadTools(server, client, SIGNER_SPEC, {
    listDescription:
      'List timestamping signers. Each signer holds a privateKey (keystore + ' +
      'alias + hash), an optional certificate (once signed), and optional ' +
      'queue/triggers. Requires the TSA license module.',
    getDescription:
      'Get a single timestamping signer by name. Returns the signer with its ' +
      'privateKey, decoded certificate (if signed) or pending dn, queue, and ' +
      'triggers. Requires the TSA module.',
  });

  // --- create ---------------------------------------------------------------
  registerCreateTool(server, client, SIGNER_SPEC, {
    description:
      'Create a new timestamping signer. A fresh signer carries NO certificate ' +
      '(the server forces it to none); supply a subject `dn` so a CSR can later ' +
      'be generated (generate_tsa_signer_csr) and the issued certificate ' +
      'imported via update. The privateKey keystore + alias must already exist. ' +
      'Once signed, the certificate MUST carry the timeStamping EKU as its only ' +
      'EKU, flagged critical. Requires the TSA module.',
    mandatoryFields: ['name', 'private_key', 'dn'],
    inputSchema: z.object({
      name: z
        .string()
        .describe('Unique signer name (immutable primary key). Ask the user.'),
      dn: z
        .string()
        .describe(
          'Subject DN for the future CSR (e.g. "CN=MY-TSA-SIGNER"). Mandatory ' +
            'at create since the signer has no certificate yet.',
        ),
      private_key: privateKeyShape.describe(
        'Private key reference. MANDATORY sub-fields: keystore (existing ' +
          'keystore name) and name (private-key alias inside it) - ask the user ' +
          'for both, do not infer. Optional: hash_algorithm, use_pss.',
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
          'Trigger names fired on ON_TSA_SIGNER_EXPIRATION. Each must reference ' +
            'an existing trigger runnable on that event.',
        ),
    }),
    buildPayload: (args) => {
      const body: Record<string, unknown> = {
        name: args.name,
        dn: args.dn,
        privateKey: mapPrivateKey(args.private_key),
      };
      if (args.queue !== undefined) body['queue'] = args.queue;
      const triggers = mapTriggers(args.on_expiration_triggers);
      if (triggers !== undefined) body['triggers'] = triggers;
      return body;
    },
  });

  // --- update ---------------------------------------------------------------
  registerUpdateTool(server, client, SIGNER_SPEC, {
    description:
      'Update a timestamping signer (full-replace, keyed by name; name is ' +
      'required as the lookup key). To attach a signed certificate to a signer ' +
      'that has none, pass certificate_pem. NOTE: once the signer has a ' +
      'certificate, its certificate and privateKey keystore/alias are immutable ' +
      '(only hash_algorithm / use_pss are applied) and dn is cleared. Pass only ' +
      'the fields you want to change; any field you omit keeps its current value ' +
      '(the tool fetches the existing record and merges your changes). To null an ' +
      'optional field use clear_fields. Requires the TSA module.',
    inputSchema: z.object({
      name: z.string().describe('Signer name to update (lookup key).'),
      certificate_pem: z
        .string()
        .optional()
        .describe(
          'PEM-encoded X.509 certificate to attach (only effective while the ' +
            'signer has no certificate). Must carry the timeStamping EKU as its ' +
            'only EKU, flagged critical.',
        ),
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
        .describe('Trigger names for ON_TSA_SIGNER_EXPIRATION.'),
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
      // certificate is a write-only PEM string on input.
      if (args.certificate_pem !== undefined) {
        overrides['certificate'] = args.certificate_pem;
      }
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
    description:
      'Delete a timestamping signer by name. Requires the TSA module.',
    deleteConstraints:
      'Fails (403 TIMESTAMPING-SIGNER-005) if any TSA still references this ' +
      'signer; reassign or delete the referencing TSAs first.',
  });

  // --- generate CSR ---------------------------------------------------------
  registerTool(
    server,
    'generate_tsa_signer_csr',
    {
      description:
        'Generate a PKCS#10 certificate-signing request (CSR) for a ' +
        "timestamping signer, using the signer's dn and privateKey. Returns the " +
        'CSR as a PEM block (-----BEGIN CERTIFICATE REQUEST-----), NOT JSON. ' +
        'Typically called on a signer that has a dn but no certificate yet; the ' +
        'issued certificate is imported afterwards via update_tsa_signer. ' +
        'Requires MANAGE permission and the TSA module.\n' +
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
}
