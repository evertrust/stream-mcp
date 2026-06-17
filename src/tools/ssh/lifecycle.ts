/**
 * SSH lifecycle tools: enroll, revoke (polymorphic), list-requestable-templates.
 * Endpoints: POST /ssh/lifecycle/enroll, POST /ssh/lifecycle/revoke,
 * GET /ssh/lifecycle/templates?permission=.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import { buildListResponse, buildMutateResponse } from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';

import { SSH_CERTIFICATE_TYPES, SSH_LIFECYCLE_PERMISSIONS } from './enums.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const DURATION_RE =
  /^[0-9]+ *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;

const durationSchema = z
  .string()
  .regex(DURATION_RE, 'FiniteDuration like "12 hours" / "30 days".');

// ---------------------------------------------------------------------------
// enroll_ssh_certificate
// ---------------------------------------------------------------------------
//
// The subject public key is conveyed as an OpenSSH pub string. template carries
// the template name plus optional overrides (each gated by CA overridePermissions).

const ENROLL_TEMPLATE_SCHEMA = z
  .object({
    name: z.string().min(1).describe('Existing, ENABLED template name.'),
    type: z
      .enum(SSH_CERTIFICATE_TYPES)
      .optional()
      .describe('Override type (only if CA overridePermissions.type=true).'),
    lifetime: durationSchema
      .optional()
      .describe(
        'Override lifetime (only if CA overridePermissions.lifetime=true).',
      ),
    backdate: durationSchema
      .optional()
      .describe(
        'Override backdate (only if CA overridePermissions.backdate=true).',
      ),
  })
  .describe('Template selector + optional per-request overrides.');

const ENROLL_INPUT = z.object({
  ca: z
    .string()
    .min(1)
    .describe('Target SSH CA name (must be ready + enroll-enabled).'),
  public_key: z
    .string()
    .min(1)
    .describe(
      'OpenSSH public key to certify, e.g. "ssh-ed25519 AAAA... user@host".',
    ),
  template: ENROLL_TEMPLATE_SCHEMA,
  principals: z
    .array(z.string())
    .describe(
      'Principals to embed (usernames for USER, hostnames for HOST). May be ' +
        'empty if the template policy allows.',
    ),
});

function buildEnrollPayload(
  args: z.infer<typeof ENROLL_INPUT>,
): Record<string, unknown> {
  const template: Record<string, unknown> = { name: args.template.name };
  if (args.template.type !== undefined) template['type'] = args.template.type;
  if (args.template.lifetime !== undefined) {
    template['lifetime'] = args.template.lifetime;
  }
  if (args.template.backdate !== undefined) {
    template['backdate'] = args.template.backdate;
  }
  return {
    ca: args.ca,
    publicKey: args.public_key,
    template,
    principals: args.principals,
  };
}

function registerEnroll(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'enroll_ssh_certificate',
    {
      description:
        'Enroll (issue) an SSH certificate by signing an OpenSSH public key ' +
        'against a ready SSH CA + enabled template. Provide principals and ' +
        'optionally override type/lifetime/backdate (only if the CA permits). ' +
        'Returns the full signed certificate (serial is a string).',
      inputSchema: ENROLL_INPUT,
    },
    async (args) => {
      const payload = buildEnrollPayload(args);
      const result = await client.post<Record<string, unknown>>(
        '/api/v1/ssh/lifecycle/enroll',
        payload,
      );
      return text(
        buildMutateResponse({
          action: 'enrolled',
          kind: 'ssh_certificate',
          name: (result?.['keyId'] as string | undefined) ?? args.template.name,
          data: result ?? undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// revoke_ssh_certificate
// ---------------------------------------------------------------------------
//
// Polymorphic identification: an OpenSSH `certificate` (wins; serial/ca ignored)
// OR a (serial + ca) pair. serial is a decimal string.

const REVOKE_INPUT = z.object({
  certificate: z
    .string()
    .optional()
    .describe(
      'OpenSSH certificate to revoke. If given, serial/ca are ignored.',
    ),
  serial: z
    .string()
    .optional()
    .describe('Decimal serial of the certificate to revoke (requires ca).'),
  ca: z.string().optional().describe('CA name (requires serial).'),
  expected_serial: z
    .string()
    .optional()
    .describe(
      'Safety confirmation for the serial+ca path: must exactly equal `serial`. ' +
        'Revocation is irreversible, so echo the serial to confirm the target. ' +
        'Not needed when revoking by `certificate` (it is self-identifying).',
    ),
});

function registerRevoke(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'revoke_ssh_certificate',
    {
      description:
        'Revoke an SSH certificate, identified EITHER by its OpenSSH ' +
        '`certificate` OR by `serial`+`ca` (serial is a decimal string). ' +
        'Idempotent: an already-revoked or expired cert returns its current ' +
        'state.',
      inputSchema: REVOKE_INPUT,
    },
    async (args) => {
      const hasCert = !!args.certificate;
      const hasSerial = !!args.serial;
      const hasCa = !!args.ca;

      const payload: Record<string, unknown> = {};
      let name: string;

      if (hasCert) {
        payload['certificate'] = args.certificate;
        name = 'certificate (by OpenSSH cert)';
      } else if (hasSerial && hasCa) {
        // Irreversible action: require an explicit serial echo to confirm the target.
        if (args.expected_serial !== args.serial) {
          throw new StreamError(422, {
            errorCode: 'REVOKE-CONFIRM',
            message:
              'Revocation is irreversible. Pass expected_serial equal to serial ' +
              'to confirm the certificate you are revoking.',
            remediation:
              'Set expected_serial to the same value as serial (the exact target serial).',
          });
        }
        payload['serial'] = args.serial;
        payload['ca'] = args.ca;
        name = `${args.ca}/${args.serial}`;
      } else {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message:
            'Identify the certificate by `certificate` (OpenSSH cert) OR by ' +
            'both `serial` and `ca`.',
          remediation: 'Pass certificate, or pass serial together with ca.',
        });
      }

      const result = await client.post<Record<string, unknown>>(
        '/api/v1/ssh/lifecycle/revoke',
        payload,
      );
      return text(
        buildMutateResponse({
          action: 'revoked',
          kind: 'ssh_certificate',
          name: (result?.['keyId'] as string | undefined) ?? name,
          data: result ?? undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// list_requestable_ssh_templates
// ---------------------------------------------------------------------------
//
// GET /ssh/lifecycle/templates?permission= (204 -> []). Returns an array of
// { ca, templates: [...] }. Default permission = search.

const LIST_TEMPLATES_INPUT = z.object({
  permission: z
    .enum(SSH_LIFECYCLE_PERMISSIONS)
    .optional()
    .describe(
      'Filter requestable templates by permission: enroll, revoke, or ' +
        'search (default search).',
    ),
});

function registerListTemplates(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'list_requestable_ssh_templates',
    {
      description:
        'List the SSH CA/template combinations the caller may request for a ' +
        'given permission (enroll/revoke/search). Returns `{ ca, templates[] }` ' +
        'entries; empty when nothing is requestable.',
      inputSchema: LIST_TEMPLATES_INPUT,
    },
    async (args) => {
      const params = args.permission
        ? new URLSearchParams({ permission: args.permission })
        : undefined;
      const items = await client.getList<Record<string, unknown>>(
        '/api/v1/ssh/lifecycle/templates',
        params,
      );
      return text(
        buildListResponse(items, items.length, 'requestable-ssh-template'),
      );
    },
  );
}

export function registerSshLifecycleTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerEnroll(server, client);
  registerRevoke(server, client);
  registerListTemplates(server, client);
}
