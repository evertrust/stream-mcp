/**
 * SSH Certificate Template CRUD: list_ssh_templates, get_ssh_template,
 * create_ssh_template, update_ssh_template, delete_ssh_template.
 *
 * Routes mounted at /api/v1/ssh/templates. Contract: docs/audit/ssh.md.
 *
 * Quirks honored:
 *  - PUT-on-collection-root full-replace keyed by body `name` (putOnCollection).
 *  - list 204 -> [] (scaffold uses client.getList).
 *  - `id` server-managed -> stripFields ['id']; never sent.
 *  - `name` immutable; `enabled` and `lifetime` mandatory.
 *  - authorizedKeyTypes server-validated whitelist.
 *  - DELETE blocked (SSH-TEMPLATE-005) while a valid certificate uses it.
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

import { SSH_AUTHORIZED_KEY_TYPES, SSH_CERTIFICATE_TYPES } from './enums.js';

const KNOWLEDGE_REF = 'docs/audit/ssh.md';

const DURATION_RE =
  /^[0-9]+ *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;

const durationSchema = z
  .string()
  .regex(
    DURATION_RE,
    'FiniteDuration like "30 days" / "36 days" / "5 minutes".',
  );

const principalPolicySchema = z
  .object({
    min: z
      .number()
      .int()
      .positive()
      .optional()
      .describe('Optional. Min number of principals (must be > 0).'),
    max: z
      .number()
      .int()
      .positive()
      .optional()
      .describe('Optional. Max number of principals (must be > 0 and >= min).'),
    regex: z
      .string()
      .optional()
      .describe('Optional. Java regex each principal must fully match.'),
  })
  .describe(
    'Optional. Constraints on enroll principals. All sub-fields optional.',
  );

function buildPrincipalPolicy(
  p: z.infer<typeof principalPolicySchema>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (p.min !== undefined) out['min'] = p.min;
  if (p.max !== undefined) out['max'] = p.max;
  if (p.regex !== undefined) out['regex'] = p.regex;
  return out;
}

function buildTemplatePayload(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (args['name'] !== undefined) out['name'] = args['name'];
  if (args['enabled'] !== undefined) out['enabled'] = args['enabled'];
  if (args['type'] !== undefined) out['type'] = args['type'];
  if (args['lifetime'] !== undefined) out['lifetime'] = args['lifetime'];
  if (args['backdate'] !== undefined) out['backdate'] = args['backdate'];
  if (args['authorized_key_types'] !== undefined) {
    out['authorizedKeyTypes'] = args['authorized_key_types'];
  }
  if (args['principal_policy'] !== undefined) {
    out['principalPolicy'] = buildPrincipalPolicy(
      args['principal_policy'] as z.infer<typeof principalPolicySchema>,
    );
  }
  return out;
}

const SPEC: ConfigSpec = {
  noun: 'ssh_template',
  nounPlural: 'ssh_templates',
  label: 'SSH certificate template',
  routeCollection: '/api/v1/ssh/templates',
  routeItem: '/api/v1/ssh/templates/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  stripFields: ['id'],
  putOnCollection: true,
  knowledgeRef: KNOWLEDGE_REF,
};

const optionalShape = {
  type: z
    .enum(SSH_CERTIFICATE_TYPES)
    .optional()
    .describe(
      'Optional. Certificate type (allowed values: USER, HOST). If omitted, ' +
        'the enroll request supplies it (subject to CA override).',
    ),
  backdate: durationSchema
    .optional()
    .describe('Optional. Backdate validity start (FiniteDuration).'),
  authorized_key_types: z
    .array(z.enum(SSH_AUTHORIZED_KEY_TYPES))
    .optional()
    .describe(
      'Optional. Whitelist of allowed SSH key types (allowed values: ' +
        'ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ' +
        'ecdsa-sha2-nistp521, ssh-ed25519).',
    ),
  principal_policy: principalPolicySchema.optional(),
};

export function registerSshTemplateTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List SSH certificate templates. Returns the full template body for ' +
      'each. Empty/forbidden collections return [].',
    getDescription:
      'Get a single SSH certificate template by name (disabled templates are ' +
      'returned too).',
  });

  registerCreateTool(server, client, SPEC, {
    description:
      'Create an SSH certificate template. MANDATORY: name, enabled, lifetime ' +
      '(FiniteDuration). Ask the user for each; do not infer or invent them ' +
      '(especially the immutable name). authorizedKeyTypes is a server-' +
      'validated whitelist. Fails (SSH-TEMPLATE-004) if the name already exists.',
    mandatoryFields: ['name', 'enabled', 'lifetime'],
    inputSchema: z.object({
      name: z
        .string()
        .min(1)
        .describe(
          'MANDATORY. Immutable template name (primary key). Ask the user; ' +
            'do not invent it.',
        ),
      enabled: z
        .boolean()
        .describe(
          'MANDATORY. Whether the template is enabled. Disabled templates ' +
            'are not usable for enroll and are excluded from the requestable ' +
            'list.',
        ),
      lifetime: durationSchema.describe(
        'MANDATORY. Certificate validity (FiniteDuration), e.g. "30 days".',
      ),
      ...optionalShape,
    }),
    buildPayload: (args) =>
      buildTemplatePayload(args as Record<string, unknown>),
  });

  registerUpdateTool(server, client, SPEC, {
    description:
      'Update an SSH certificate template by name (PUT full-replace keyed by ' +
      'body name). GET -> strip id -> merge supplied fields -> PUT. Any optional ' +
      'field you OMIT keeps its current value (the tool re-sends it from the ' +
      'existing record); use clear_fields to explicitly null an optional field.',
    inputSchema: z.object({
      name: z
        .string()
        .min(1)
        .describe(
          'REQUIRED. Immutable template name used as the lookup key for the ' +
            'full-replace update. Ask the user; do not infer.',
        ),
      enabled: z
        .boolean()
        .optional()
        .describe(
          'Optional on update. Whether the template is enabled. If omitted, ' +
            'the existing value is kept.',
        ),
      lifetime: durationSchema
        .optional()
        .describe(
          'Optional on update. Certificate validity (FiniteDuration), e.g. ' +
            '"30 days". If omitted, the existing value is kept.',
        ),
      ...optionalShape,
      clear_fields: z
        .array(z.string())
        .optional()
        .describe(
          'Optional wire field names to null (e.g. ["type","backdate"]). ' +
            'Cannot target id or name.',
        ),
    }),
    buildOverrides: (args) => {
      const { name: _name, clear_fields: _clear, ...rest } = args;
      return buildTemplatePayload(rest as Record<string, unknown>);
    },
  });

  registerDeleteTool(server, client, SPEC, {
    description: 'Delete an SSH certificate template by name.',
    deleteConstraints:
      'Blocked (SSH-TEMPLATE-005) while a valid certificate uses this template ' +
      '(checked BEFORE the not-found check). On success cascades cleanup into ' +
      'account and role permissions.',
  });
}
