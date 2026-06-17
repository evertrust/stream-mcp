/**
 * SSH Certificate Authority CRUD: list_ssh_cas, get_ssh_ca, create_ssh_ca,
 * update_ssh_ca, delete_ssh_ca.
 *
 * Routes mounted at /api/v1/ssh/cas. Contract: docs/audit/ssh.md.
 *
 * Quirks honored:
 *  - PUT-on-collection-root full-replace keyed by body `name` (putOnCollection).
 *  - list 204 -> [] (scaffold uses client.getList).
 *  - `publicKey` is server-DERIVED: omitted on create, stripped on update (the
 *    server recomputes it from the keystore private key). `id` server-assigned.
 *  - `name` immutable primary key.
 *  - krlPolicy.validity is mandatory; enroll + enforceKeyUnicity are mandatory.
 *  - privateKey is a reference object {keystore, name, hashAlgorithm?, usePSS?}
 *    (NOT a secret holder — it names an existing keystore key).
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import {
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
  type ConfigSpec,
} from '../_scaffold.js';

import { SSH_HASH_ALGORITHMS } from './enums.js';

const KNOWLEDGE_REF = 'docs/audit/ssh.md';

const DURATION_RE =
  /^[0-9]+ *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;

const durationSchema = z
  .string()
  .regex(
    DURATION_RE,
    'FiniteDuration like "14 days" / "28 days" / "12 hours".',
  );

// Quartz cron strings, e.g. "0 0 0/4 * * ?". Pass through verbatim.
const cronSchema = z
  .string()
  .min(1)
  .describe('Quartz cron expression, e.g. "0 0 0/4 * * ?".');

// ---------------------------------------------------------------------------
// Nested schemas
// ---------------------------------------------------------------------------

const privateKeySchema = z
  .object({
    keystore: z
      .string()
      .min(1)
      .describe('MANDATORY. Existing keystore name. Ask the user.'),
    name: z
      .string()
      .min(1)
      .describe(
        'MANDATORY. Private-key alias inside the keystore. Ask the user.',
      ),
    hash_algorithm: z
      .enum(SSH_HASH_ALGORITHMS)
      .optional()
      .describe('Hash algorithm. Omit for Ed25519 keys (no hash).'),
    use_pss: z.boolean().optional().describe('RSA-PSS toggle.'),
  })
  .describe(
    'Reference to an existing keystore key (RSA/EC/Ed25519). Not a secret.',
  );

const overridePermissionsSchema = z
  .object({
    type: z
      .boolean()
      .optional()
      .describe(
        'Optional. Allow enroll requests to override certificate type.',
      ),
    backdate: z
      .boolean()
      .optional()
      .describe('Optional. Allow enroll requests to override backdate.'),
    lifetime: z
      .boolean()
      .optional()
      .describe('Optional. Allow enroll requests to override lifetime.'),
  })
  .describe(
    'Optional. Which enroll-request fields this CA permits overriding. All ' +
      'sub-fields optional; absent is treated as false.',
  );

const triggersSchema = z
  .object({
    on_krl_generation: z
      .array(z.string())
      .optional()
      .describe('Optional. Trigger names fired on KRL generation.'),
    on_krl_generation_error: z
      .array(z.string())
      .optional()
      .describe('Optional. Trigger names fired on KRL generation error.'),
    on_krl_generation_recover: z
      .array(z.string())
      .optional()
      .describe('Optional. Trigger names fired on KRL generation recovery.'),
    on_krl_sync: z
      .array(z.string())
      .optional()
      .describe('Optional. Trigger names fired on KRL sync.'),
    on_krl_sync_error: z
      .array(z.string())
      .optional()
      .describe('Optional. Trigger names fired on KRL sync error.'),
  })
  .describe(
    'Optional. KRL-related trigger hooks (arrays of trigger names). All ' +
      'sub-fields optional.',
  );

const krlPolicySchema = z
  .object({
    validity: durationSchema.describe(
      'KRL validity window, e.g. "14 days". MANDATORY.',
    ),
    hard_generation: cronSchema
      .optional()
      .describe('Optional. Quartz cron for full KRL regeneration.'),
    lazy_generation: cronSchema
      .optional()
      .describe('Optional. Quartz cron for lazy KRL regeneration.'),
  })
  .describe('KRL generation/validity policy. validity is mandatory.');

// ---------------------------------------------------------------------------
// Wire payload mapping
// ---------------------------------------------------------------------------

function buildPrivateKey(
  pk: z.infer<typeof privateKeySchema>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    keystore: pk.keystore,
    name: pk.name,
  };
  if (pk.hash_algorithm !== undefined) out['hashAlgorithm'] = pk.hash_algorithm;
  if (pk.use_pss !== undefined) out['usePSS'] = pk.use_pss;
  return out;
}

function buildTriggers(
  t: z.infer<typeof triggersSchema>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (t.on_krl_generation !== undefined) {
    out['onKRLGeneration'] = t.on_krl_generation;
  }
  if (t.on_krl_generation_error !== undefined) {
    out['onKRLGenerationError'] = t.on_krl_generation_error;
  }
  if (t.on_krl_generation_recover !== undefined) {
    out['onKRLGenerationRecover'] = t.on_krl_generation_recover;
  }
  if (t.on_krl_sync !== undefined) out['onKRLSync'] = t.on_krl_sync;
  if (t.on_krl_sync_error !== undefined) {
    out['onKRLSyncError'] = t.on_krl_sync_error;
  }
  return out;
}

function buildKrlPolicy(
  p: z.infer<typeof krlPolicySchema>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { validity: p.validity };
  if (p.hard_generation !== undefined)
    out['hardGeneration'] = p.hard_generation;
  if (p.lazy_generation !== undefined)
    out['lazyGeneration'] = p.lazy_generation;
  return out;
}

/**
 * Map a CA tool-input args object to the camelCase wire body. Used by both
 * create (all mandatory present) and update (everything optional -> only set
 * what is supplied). `publicKey` is intentionally never written.
 */
function buildCaPayload(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (args['name'] !== undefined) out['name'] = args['name'];
  if (args['private_key'] !== undefined) {
    out['privateKey'] = buildPrivateKey(
      args['private_key'] as z.infer<typeof privateKeySchema>,
    );
  }
  if (args['queue'] !== undefined) out['queue'] = args['queue'];
  if (args['enroll'] !== undefined) out['enroll'] = args['enroll'];
  if (args['enforce_key_unicity'] !== undefined) {
    out['enforceKeyUnicity'] = args['enforce_key_unicity'];
  }
  if (args['override_permissions'] !== undefined) {
    out['overridePermissions'] = (() => {
      const op = args['override_permissions'] as z.infer<
        typeof overridePermissionsSchema
      >;
      const o: Record<string, unknown> = {};
      if (op.type !== undefined) o['type'] = op.type;
      if (op.backdate !== undefined) o['backdate'] = op.backdate;
      if (op.lifetime !== undefined) o['lifetime'] = op.lifetime;
      return o;
    })();
  }
  if (args['triggers'] !== undefined) {
    out['triggers'] = buildTriggers(
      args['triggers'] as z.infer<typeof triggersSchema>,
    );
  }
  if (args['krl_policy'] !== undefined) {
    out['krlPolicy'] = buildKrlPolicy(
      args['krl_policy'] as z.infer<typeof krlPolicySchema>,
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// ConfigSpec
// ---------------------------------------------------------------------------

const SPEC: ConfigSpec = {
  noun: 'ssh_ca',
  nounPlural: 'ssh_cas',
  label: 'SSH Certificate Authority',
  routeCollection: '/api/v1/ssh/cas',
  routeItem: '/api/v1/ssh/cas/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  // publicKey is rich-on-read / server-derived (the server recomputes it from
  // the keystore private key); id is server-assigned. Both must be stripped so
  // the PUT never sends a server-managed value.
  stripFields: ['id', 'publicKey'],
  putOnCollection: true,
  knowledgeRef: KNOWLEDGE_REF,
};

// Shared optional shape reused by create + update (update makes mandatory
// fields optional too).
const optionalShape = {
  queue: z
    .string()
    .optional()
    .describe('Optional queue name (must reference an existing queue).'),
  override_permissions: overridePermissionsSchema.optional(),
  triggers: triggersSchema.optional(),
};

export function registerSshCaTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List all SSH Certificate Authorities. Empty/forbidden collections ' +
      'return []. `publicKey` is the server-derived OpenSSH public key (a CA ' +
      'is "ready" iff publicKey is present).',
    getDescription:
      'Get a single SSH Certificate Authority by name. Returns the full ' +
      'object including the server-derived `publicKey`.',
  });

  registerCreateTool(server, client, SPEC, {
    description:
      'Create an SSH Certificate Authority. MANDATORY: name, private_key ' +
      '(keystore + name), enroll, enforce_key_unicity, krl_policy (validity). ' +
      'Ask the user for each; do not infer or invent them (especially the ' +
      'immutable name). The signing key is referenced via private_key ' +
      '{keystore, name}; the server DERIVES publicKey from it (never send ' +
      'publicKey). Fails (SSH-CA-004) if the name already exists.',
    mandatoryFields: [
      'name',
      'private_key',
      'enroll',
      'enforce_key_unicity',
      'krl_policy',
    ],
    inputSchema: z.object({
      name: z
        .string()
        .min(1)
        .describe(
          'MANDATORY. Immutable CA name (primary key). Ask the user; do not ' +
            'invent it.',
        ),
      private_key: privateKeySchema,
      enroll: z
        .boolean()
        .describe('MANDATORY. If false, enrollment on this CA is rejected.'),
      enforce_key_unicity: z
        .boolean()
        .describe(
          'MANDATORY. If true, an enroll fails when the key thumbprint ' +
            'already exists on this CA.',
        ),
      krl_policy: krlPolicySchema,
      ...optionalShape,
    }),
    buildPayload: (args) => buildCaPayload(args as Record<string, unknown>),
  });

  registerUpdateTool(server, client, SPEC, {
    description:
      'Update an SSH Certificate Authority by name (PUT full-replace keyed by ' +
      'body name). GET -> strip id/publicKey -> merge supplied fields -> PUT. ' +
      'publicKey is re-derived server-side from privateKey. Any optional field ' +
      'you OMIT keeps its current value (the tool re-sends it from the existing ' +
      'record); use clear_fields to explicitly null an optional field.',
    inputSchema: z.object({
      name: z
        .string()
        .min(1)
        .describe(
          'REQUIRED. Immutable CA name used as the lookup key for the ' +
            'full-replace update. Ask the user; do not infer.',
        ),
      private_key: privateKeySchema
        .optional()
        .describe(
          'Optional on update. Reference to the signing keystore key ' +
            '{keystore, name}. If omitted, the existing privateKey is kept.',
        ),
      enroll: z
        .boolean()
        .optional()
        .describe(
          'Optional on update. If false, enrollment on this CA is rejected.',
        ),
      enforce_key_unicity: z
        .boolean()
        .optional()
        .describe(
          'Optional on update. If true, an enroll fails when the key ' +
            'thumbprint already exists on this CA.',
        ),
      krl_policy: krlPolicySchema
        .optional()
        .describe(
          'Optional on update. KRL generation/validity policy; validity is ' +
            'mandatory inside krl_policy when supplied.',
        ),
      ...optionalShape,
      clear_fields: z
        .array(z.string())
        .optional()
        .describe(
          'Optional wire field names to null (e.g. ["queue","triggers"]). ' +
            'Cannot target id, publicKey or name.',
        ),
    }),
    buildOverrides: (args) => {
      const { name: _name, clear_fields: _clear, ...rest } = args;
      return buildCaPayload(rest as Record<string, unknown>);
    },
  });

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete an SSH Certificate Authority by name. On success cascades: ' +
      'removes the stored KRL + KRL info and strips CA permissions from ' +
      'accounts and roles.',
    deleteConstraints:
      'Blocked (SSH-CA-005) while any SSH certificate references this CA.',
  });
}
