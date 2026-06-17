/**
 * Crypto keystores: polymorphic (software / pkcs11 / aws / akv / gcp).
 *
 * list/get use the standard read scaffold. create/update are custom because the
 * body is polymorphic by `type` and PKCS#11 carries a write-only `pin` secret
 * (`{clear}` in, `{}` out) that must be RETAINED on update when not supplied.
 *
 * Wire quirks (docs/audit/crypto.md):
 *   - PUT on the COLLECTION root (full-replace; `name` in body is the lookup key).
 *   - `status` is server-computed and stripped from any input.
 *   - `id` is server-assigned; preserved from previous on update.
 *   - `type` is immutable in practice (must match the previous record on update).
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import {
  registerReadTools,
  getStripMergePutExplicit,
  type ConfigSpec,
} from '../_scaffold.js';
import { KEYSTORE_TYPES, NAME_REGEX } from './enums.js';

const KEYSTORE_SPEC: ConfigSpec = {
  noun: 'keystore',
  nounPlural: 'keystores',
  label: 'keystore',
  routeCollection: '/api/v1/crypto/keystores',
  routeItem: '/api/v1/crypto/keystores/{name}',
  idField: 'name',
  immutableKeys: ['name', 'type'],
  // `status` is server-computed; `id` is server-assigned. `pin` is a write-only
  // secret returned sanitized as `{}` — strip it so update never re-sends it
  // unless the user supplies a fresh value (then the previous PIN is retained).
  stripFields: ['id', 'status', 'pin'],
  putOnCollection: true,
};

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// ---------------------------------------------------------------------------
// Shared input fields
// ---------------------------------------------------------------------------

const commonFields = {
  name: z
    .string()
    .regex(NAME_REGEX, 'Must match [0-9a-zA-Z-_.]+')
    .describe(
      'Keystore name (immutable primary key; regex [0-9a-zA-Z-_.]+). Ask the user — never invent it.',
    ),
  description: z
    .string()
    .optional()
    .describe('Optional. Free-text description.'),
} as const;

// PKCS#11
const pkcs11Fields = {
  library: z
    .string()
    .describe('pkcs11 — MANDATORY. Path to the PKCS#11 .so library.'),
  slot: z.number().int().describe('pkcs11 — MANDATORY. PKCS#11 slot ID.'),
  pin: z
    .string()
    .optional()
    .describe(
      'pkcs11 — optional. PKCS#11 PIN (write-only secret; ask the user). On update omit to retain the existing PIN.',
    ),
  rsa_x931_mode: z
    .boolean()
    .describe(
      'pkcs11 — MANDATORY. Enable RSA X9.31 signing mode (true/false).',
    ),
  pool_size: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('pkcs11 — optional. Session pool size (must be > 0).'),
  user_type: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('pkcs11 — optional. PKCS#11 user type (default 1; must be > 0).'),
} as const;

// AWS KMS
const awsFields = {
  region: z
    .string()
    .optional()
    .describe('aws — optional. AWS region, e.g. us-east-1.'),
  credentials: z
    .string()
    .optional()
    .describe(
      'aws/akv/gcp — optional. Name of an existing credentials object (secret reference). ' +
        'aws: `password` creds (login=access key, password=secret key); ' +
        'akv: `password` creds (login=clientId, password=clientSecret); ' +
        'gcp: `raw` creds holding the GCP service-account JSON.',
    ),
  role_arn: z
    .string()
    .optional()
    .describe('aws — optional. IAM role ARN to assume.'),
  endpoint: z
    .string()
    .optional()
    .describe('aws — optional. KMS endpoint override (URI).'),
  proxy: z
    .string()
    .optional()
    .describe('aws/akv/gcp — optional. Existing HTTP proxy reference.'),
  timeout: z
    .string()
    .optional()
    .describe(
      'aws/akv/gcp — optional. Request timeout, e.g. "5 seconds" (default).',
    ),
} as const;

// Azure Key Vault
const akvFields = {
  vault_url: z
    .string()
    .describe('akv — MANDATORY (required when type=akv). Key Vault URL.'),
  tenant: z.string().optional().describe('akv — optional. Azure tenant ID.'),
  credentials: z
    .string()
    .optional()
    .describe(
      'akv — optional. Name of existing `password` credentials (login=clientId, password=clientSecret).',
    ),
} as const;

// Google Cloud KMS
const gcpFields = {
  project: z
    .string()
    .describe('gcp — MANDATORY (required when type=gcp). GCP project ID.'),
  location: z
    .string()
    .describe(
      'gcp — MANDATORY (required when type=gcp). KMS location, e.g. global.',
    ),
  key_ring: z
    .string()
    .describe('gcp — MANDATORY (required when type=gcp). KMS key ring name.'),
  credentials: z
    .string()
    .optional()
    .describe(
      'gcp — optional. Name of existing `raw` credentials holding the GCP SA JSON.',
    ),
} as const;

const keystoreInputSchema = z.object({
  type: z
    .enum(KEYSTORE_TYPES)
    .describe(
      'Keystore type (immutable). One of: software, pkcs11, aws, akv, gcp.',
    ),
  ...commonFields,
  // pkcs11
  library: pkcs11Fields.library.optional(),
  slot: pkcs11Fields.slot.optional(),
  pin: pkcs11Fields.pin,
  rsa_x931_mode: pkcs11Fields.rsa_x931_mode.optional(),
  pool_size: pkcs11Fields.pool_size,
  user_type: pkcs11Fields.user_type,
  // aws
  region: awsFields.region,
  role_arn: awsFields.role_arn,
  endpoint: awsFields.endpoint,
  // akv
  vault_url: akvFields.vault_url.optional(),
  tenant: akvFields.tenant,
  // gcp
  project: gcpFields.project.optional(),
  location: gcpFields.location.optional(),
  key_ring: gcpFields.key_ring.optional(),
  // shared across cloud types
  credentials: awsFields.credentials,
  proxy: awsFields.proxy,
  timeout: awsFields.timeout,
});

type KeystoreInput = z.infer<typeof keystoreInputSchema>;

// ---------------------------------------------------------------------------
// Per-type payload construction + validation
// ---------------------------------------------------------------------------

/** Add a key only when value is defined (skips undefined optionals). */
function set(out: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== undefined) out[key] = value;
}

/**
 * Validate type-required fields and build the per-type camelCase wire body
 * (excluding name/type which the caller adds). `includePin` toggles whether the
 * write-only PIN is emitted (create: always when present; update: only when the
 * user supplied a new one).
 */
function buildTypeBody(args: KeystoreInput): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  switch (args.type) {
    case 'software':
      break;
    case 'pkcs11': {
      const missing: string[] = [];
      if (args.library === undefined) missing.push('library');
      if (args.slot === undefined) missing.push('slot');
      if (args.rsa_x931_mode === undefined) missing.push('rsa_x931_mode');
      if (missing.length > 0) {
        throw new StreamError(422, {
          errorCode: 'KEYSTORE-002',
          message: `pkcs11 keystore requires: ${missing.join(', ')}.`,
          remediation: 'Ask the user for these values — do not infer them.',
        });
      }
      set(out, 'library', args.library);
      set(out, 'slot', args.slot);
      set(out, 'rsaX931Mode', args.rsa_x931_mode);
      set(out, 'poolSize', args.pool_size);
      set(out, 'userType', args.user_type);
      if (args.pin !== undefined) out['pin'] = { clear: args.pin };
      break;
    }
    case 'aws': {
      set(out, 'region', args.region);
      set(out, 'credentials', args.credentials);
      set(out, 'roleArn', args.role_arn);
      set(out, 'endpoint', args.endpoint);
      set(out, 'proxy', args.proxy);
      set(out, 'timeout', args.timeout);
      break;
    }
    case 'akv': {
      if (args.vault_url === undefined) {
        throw new StreamError(422, {
          errorCode: 'KEYSTORE-002',
          message: 'akv keystore requires: vault_url.',
          remediation: 'Ask the user for the Key Vault URL — do not infer it.',
        });
      }
      set(out, 'vaultUrl', args.vault_url);
      set(out, 'tenant', args.tenant);
      set(out, 'credentials', args.credentials);
      set(out, 'proxy', args.proxy);
      set(out, 'timeout', args.timeout);
      break;
    }
    case 'gcp': {
      const missing: string[] = [];
      if (args.project === undefined) missing.push('project');
      if (args.location === undefined) missing.push('location');
      if (args.key_ring === undefined) missing.push('key_ring');
      if (missing.length > 0) {
        throw new StreamError(422, {
          errorCode: 'KEYSTORE-002',
          message: `gcp keystore requires: ${missing.join(', ')}.`,
          remediation: 'Ask the user for these values — do not infer them.',
        });
      }
      set(out, 'project', args.project);
      set(out, 'location', args.location);
      set(out, 'keyRing', args.key_ring);
      set(out, 'credentials', args.credentials);
      set(out, 'proxy', args.proxy);
      set(out, 'timeout', args.timeout);
      break;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export function registerKeystoreTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, KEYSTORE_SPEC, {
    listDescription:
      'List all crypto keystores (software, PKCS#11, AWS KMS, Azure Key Vault, GCP KMS) with their live healthcheck status.',
    getDescription:
      'Get a single keystore by name, with its live healthcheck status.',
  });

  // create_keystore (custom polymorphic)
  registerTool(
    server,
    'create_keystore',
    {
      description:
        'Create a crypto keystore. The body is polymorphic by `type`; mandatory fields depend on `type`:\n' +
        '- software: type, name only.\n' +
        '- pkcs11: type, name, library, slot, rsa_x931_mode (mandatory); pin, pool_size, user_type (optional).\n' +
        '- aws: type, name (mandatory); region, credentials, role_arn, endpoint, proxy, timeout (all optional).\n' +
        '- akv: type, name, vault_url (mandatory); tenant, credentials, proxy, timeout (optional).\n' +
        '- gcp: type, name, project, location, key_ring (mandatory); credentials, proxy, timeout (optional).\n' +
        'Safety tier: mutating-safe\n' +
        'MANDATORY: always type and name, plus the per-type mandatory fields listed above. ' +
        'Ask the user for every mandatory value; do NOT infer, default, or invent them. ' +
        'name is an immutable primary key — never invent it. ' +
        'pin/credentials are secrets/secret references (also ask the user).',
      inputSchema: keystoreInputSchema,
    },
    async (args: KeystoreInput) => {
      const body: Record<string, unknown> = {
        type: args.type,
        name: args.name,
        ...buildTypeBody(args),
      };
      set(body, 'description', args.description);
      const result = await client.post<Record<string, unknown>>(
        KEYSTORE_SPEC.routeCollection,
        body,
      );
      return text(
        buildMutateResponse({
          action: 'created',
          kind: 'keystore',
          name: args.name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  // update_keystore (custom polymorphic; full-replace PUT on collection root)
  registerTool(
    server,
    'update_keystore',
    {
      description:
        'Update a crypto keystore (full-replace PUT on the collection root). ' +
        'MANDATORY: name (the immutable lookup key that selects the existing record) and type. ' +
        'Ask the user for name; do not infer it. ' +
        'GET -> strip server fields (id, status, pin) -> merge -> PUT. ' +
        'This is a full replace: the current record is fetched and merged, so optional fields ' +
        'you OMIT keep their current value, but any optional field you set to a new value overwrites it. ' +
        'Provide the SAME type as the existing record (type is immutable). ' +
        'For pkcs11, omit pin to retain the existing PIN; supply pin to rotate it.\n' +
        'Safety tier: mutating-safe',
      inputSchema: keystoreInputSchema,
    },
    async (args: KeystoreInput) => {
      const overrides: Record<string, unknown> = {
        type: args.type,
        ...buildTypeBody(args),
      };
      set(overrides, 'description', args.description);
      const itemPath = `${KEYSTORE_SPEC.routeCollection}/${encodePathSegment(
        args.name,
      )}`;
      const result = await getStripMergePutExplicit(
        client,
        itemPath,
        KEYSTORE_SPEC.routeCollection,
        KEYSTORE_SPEC.stripFields,
        overrides,
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'keystore',
          name: args.name,
          data: result,
        }),
      );
    },
  );

  // delete_keystore (DELETE /:name with echo guard)
  registerTool(
    server,
    'delete_keystore',
    {
      description:
        'Delete a keystore by name. Blocked (KEYSTORE-005) if referenced by any SSH CA, ' +
        'x509 CA, OCSP signer, or Timestamping signer. A software keystore also purges its stored keys.\n' +
        'Safety tier: mutating-destructive\nRequires name confirmation via expected_name.',
      inputSchema: z.object({
        name: z.string().describe('Keystore name to delete.'),
        expected_name: z
          .string()
          .describe('Must exactly match name as a deletion safeguard.'),
      }),
    },
    async ({ name, expected_name }) => {
      if (name !== expected_name) {
        throw new StreamError(422, {
          errorCode: 'SAFETY-ECHO',
          message: `Safety check failed: expected_name='${expected_name}' does not match name='${name}'.`,
          remediation: 'Pass expected_name equal to name to confirm deletion.',
        });
      }
      await client.delete(
        `${KEYSTORE_SPEC.routeCollection}/${encodePathSegment(name)}`,
      );
      return text(JSON.stringify({ deleted: true, name, kind: 'keystore' }));
    },
  );
}
