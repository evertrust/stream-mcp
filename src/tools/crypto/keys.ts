/**
 * Crypto private keys + HSM (PKCS#11 library) inspection.
 *
 * All custom tools (no standard name-keyed CRUD shape):
 *   - list_keys    GET    /api/v1/crypto/keys/:keystore (?unusedOnly)
 *   - get_key      GET    /api/v1/crypto/keys/:keystore/:key
 *   - create_key   POST   /api/v1/crypto/keys           (keystore in body)
 *   - delete_key   DELETE /api/v1/crypto/keys/:keystore/:key (echo guard)
 *   - find_ca_keys POST   /api/v1/crypto/keys/:keystore (READ-ONLY search; ca PEM)
 *   - get_hsm_info GET    /api/v1/crypto/hsms/:library
 *   - get_hsm_slots GET   /api/v1/crypto/hsms/:library/slots
 *
 * No private/secret material is ever returned (server sanitizes).
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  buildListResponse,
  buildMutateResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';
import { MAX_LIST_ITEMS } from '../_scaffold.js';
import { KEY_ALGORITHMS, NAME_REGEX } from './enums.js';

const KEYS_ROUTE = '/api/v1/crypto/keys';
const HSMS_ROUTE = '/api/v1/crypto/hsms';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

export function registerKeyTools(
  server: McpServer,
  client: StreamClient,
): void {
  // list_keys ----------------------------------------------------------------
  registerTool(
    server,
    'list_keys',
    {
      description:
        'List the private keys on a keystore (queried live from the backing store / HSM / cloud KMS). ' +
        'Set unused_only=true to exclude keys already referenced by an SSH CA, x509 CA, OCSP signer, or Timestamping signer.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        keystore: z.string().describe('Owning keystore name.'),
        unused_only: z
          .boolean()
          .optional()
          .describe(
            'Exclude keys already referenced by a CA/signer (default false).',
          ),
        max_items: z
          .number()
          .int()
          .positive()
          .max(100)
          .default(MAX_LIST_ITEMS)
          .describe('Maximum items to return (default 50).'),
      }),
    },
    async ({ keystore, unused_only, max_items }) => {
      const params =
        unused_only === undefined
          ? undefined
          : new URLSearchParams({ unusedOnly: String(unused_only) });
      const items = await client.getList<Record<string, unknown>>(
        `${KEYS_ROUTE}/${encodePathSegment(keystore)}`,
        params,
      );
      return text(buildListResponse(items, max_items, 'key'));
    },
  );

  // get_key ------------------------------------------------------------------
  registerTool(
    server,
    'get_key',
    {
      description:
        'Get a single private key by name on a keystore (no private material is returned).\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        keystore: z.string().describe('Owning keystore name.'),
        key: z.string().describe('Key name (for AWS this is the key ARN).'),
      }),
    },
    async ({ keystore, key }) => {
      const result = await client.get(
        `${KEYS_ROUTE}/${encodePathSegment(keystore)}/${encodePathSegment(key)}`,
      );
      return text(JSON.stringify(result));
    },
  );

  // create_key ---------------------------------------------------------------
  registerTool(
    server,
    'create_key',
    {
      description:
        'Generate a new private key on a keystore. POST on the collection root — the keystore is named in the body. ' +
        'algorithm is a CFAsymmetricAlgorithm wire value (e.g. rsa-2048, ec-secp256r1, mldsa-44). ' +
        'Not every algorithm is supported by every keystore type (AWS: RSA 2048/3072/4096 + EC P256/P384/P521 only; ' +
        'the server returns KEY-002 for unsupported combinations).\n' +
        'Safety tier: mutating-safe\n' +
        'MANDATORY: name, keystore, algorithm. Ask the user for each; do NOT infer, default, or invent them. ' +
        'name is the immutable key identifier — never invent it.',
      inputSchema: z.object({
        name: z
          .string()
          .regex(NAME_REGEX, 'Must match [0-9a-zA-Z-_.]+')
          .describe(
            'Key name to create (immutable). Ask the user — never invent it.',
          ),
        keystore: z
          .string()
          .describe(
            'MANDATORY. Existing keystore name to create the key on. Ask the user.',
          ),
        algorithm: z
          .enum(KEY_ALGORITHMS)
          .describe(
            'MANDATORY. Asymmetric algorithm (CFAsymmetricAlgorithm wire value). Ask the user. ' +
              'Allowed: rsa-2048, rsa-3072, rsa-4096, rsa-8192, ec-secp256r1, ec-secp384r1, ' +
              'ec-secp521r1, ed-25519, ed-448, mldsa-44, mldsa-65, mldsa-87, mldsa-44sha512, ' +
              'mldsa-65sha512, mldsa-87sha512.',
          ),
        extractable: z
          .boolean()
          .optional()
          .describe(
            'Optional. PKCS#11/cloud honor where supported; software always extractable; AKV forces non-exportable.',
          ),
        modifiable: z.boolean().optional().describe('Optional. PKCS#11 only.'),
        hardware_protected: z
          .boolean()
          .optional()
          .describe('Optional. AKV/GCP: select an HSM-backed key when true.'),
      }),
    },
    async ({
      name,
      keystore,
      algorithm,
      extractable,
      modifiable,
      hardware_protected,
    }) => {
      // `description` is the algorithm wire field (per audit).
      const body: Record<string, unknown> = {
        name,
        keystore,
        description: algorithm,
      };
      if (extractable !== undefined) body['extractable'] = extractable;
      if (modifiable !== undefined) body['modifiable'] = modifiable;
      if (hardware_protected !== undefined)
        body['hardwareProtected'] = hardware_protected;
      const result = await client.post<Record<string, unknown>>(
        KEYS_ROUTE,
        body,
      );
      return text(
        buildMutateResponse({
          action: 'created',
          kind: 'key',
          name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
          warnings:
            result === null
              ? [
                  'Key created on GCP but not yet readable (KeyNotReadyException); fetch later with get_key.',
                ]
              : undefined,
        }),
      );
    },
  );

  // delete_key ---------------------------------------------------------------
  registerTool(
    server,
    'delete_key',
    {
      description:
        'Delete (or, for AWS KMS, disable) a private key on a keystore. ' +
        'Blocked (KEY-005) if referenced by a CA / OCSP / Timestamping signer.\n' +
        'Safety tier: mutating-destructive\nRequires key confirmation via expected_key.',
      inputSchema: z.object({
        keystore: z.string().describe('Owning keystore name.'),
        key: z.string().describe('Key name to delete.'),
        expected_key: z
          .string()
          .describe('Must exactly match key as a deletion safeguard.'),
      }),
    },
    async ({ keystore, key, expected_key }) => {
      if (key !== expected_key) {
        throw new StreamError(422, {
          errorCode: 'SAFETY-ECHO',
          message: `Safety check failed: expected_key='${expected_key}' does not match key='${key}'.`,
          remediation: 'Pass expected_key equal to key to confirm deletion.',
        });
      }
      await client.delete(
        `${KEYS_ROUTE}/${encodePathSegment(keystore)}/${encodePathSegment(key)}`,
      );
      return text(
        JSON.stringify({ deleted: true, keystore, key, kind: 'key' }),
      );
    },
  );

  // find_ca_keys (read-only POST search) -------------------------------------
  registerTool(
    server,
    'find_ca_keys',
    {
      description:
        'Find keys on a keystore whose public key matches a given CA certificate. ' +
        'Read-only search (POST). Requires the CA Stream module to be licensed. ' +
        'Provide the CA certificate as PEM.\n' +
        'Safety tier: read-only',
      // The auto-classifier does not recognize the mandated `find_` prefix; this
      // search is read-only (no state change), so mark it explicitly.
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      inputSchema: z.object({
        keystore: z.string().describe('Keystore name to search.'),
        ca: z.string().describe('The CA certificate as a PEM string.'),
        unused_only: z
          .boolean()
          .optional()
          .describe(
            'Exclude keys already referenced by a CA/signer (default false).',
          ),
      }),
    },
    async ({ keystore, ca, unused_only }) => {
      const body: Record<string, unknown> = { ca };
      if (unused_only !== undefined) body['unusedOnly'] = unused_only;
      const result = await client.post<unknown>(
        `${KEYS_ROUTE}/${encodePathSegment(keystore)}`,
        body,
      );
      const items = Array.isArray(result)
        ? (result as Record<string, unknown>[])
        : [];
      return text(buildListResponse(items, MAX_LIST_ITEMS, 'key'));
    },
  );

  // get_hsm_info -------------------------------------------------------------
  registerTool(
    server,
    'get_hsm_info',
    {
      description:
        'Load a PKCS#11 library and return its module info (libraryVersion, cryptokiVersion, manufacturerID, libraryDescription).\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        library: z
          .string()
          .describe(
            'Filesystem path to the PKCS#11 .so library (e.g. /usr/lib/softhsm/libsofthsm2.so).',
          ),
      }),
    },
    async ({ library }) => {
      const result = await client.get(
        `${HSMS_ROUTE}/${encodePathSegment(library)}`,
      );
      return text(JSON.stringify(result));
    },
  );

  // get_hsm_slots ------------------------------------------------------------
  registerTool(
    server,
    'get_hsm_slots',
    {
      description:
        'List the slots of a PKCS#11 library (id, isHardwareSlot, manufacturerID, hardwareVersion, firmwareVersion, description).\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        library: z
          .string()
          .describe('Filesystem path to the PKCS#11 .so library.'),
      }),
    },
    async ({ library }) => {
      const items = await client.getList<Record<string, unknown>>(
        `${HSMS_ROUTE}/${encodePathSegment(library)}/slots`,
      );
      return text(buildListResponse(items, MAX_LIST_ITEMS, 'hsm_slot'));
    },
  );
}
