/**
 * X509 lifecycle tools: enroll (CSR-based), revoke (polymorphic), and
 * list-requestable-templates.
 * Endpoints: POST /lifecycle/enroll, POST /lifecycle/revoke,
 * GET /lifecycle/templates?permission=.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import { buildListResponse, buildMutateResponse } from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';
import {
  DATA_SOURCING_STRATEGIES,
  EMPTY_EXTENSION_TYPES,
  EXTENSION_TYPES,
  KEY_USAGE_ELEMENTS,
  LIFECYCLE_PERMISSIONS,
  REVOCATION_REASONS,
  SAN_TYPES,
} from './enums.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const DN_ELEMENT_RE = /^[a-z]+\.\d+$/;

// ---------------------------------------------------------------------------
// enroll_certificate
// ---------------------------------------------------------------------------
//
// CSR-only: the public key is conveyed in the PKCS#10 PEM. There is NO
// centralized/server-side key-gen on this v1 endpoint, and no owner/labels/
// metadata on this request model.

const KU_SCHEMA = z
  .object({
    critical: z.boolean(),
    values: z.array(z.enum(KEY_USAGE_ELEMENTS)),
  })
  .strict();

const EKU_ELEMENT_SCHEMA = z
  .object({
    name: z.string(),
    oid: z.string().describe('A valid OID, e.g. 1.3.6.1.5.5.7.3.1.'),
    // The server uses Json.format (not useDefaults) for ExtendedKeyUsageElement,
    // so `custom` is REQUIRED on the wire (omitting it -> 400 path.missing).
    custom: z.boolean(),
  })
  .strict();

const EKU_SCHEMA = z
  .object({
    critical: z.boolean(),
    values: z.array(EKU_ELEMENT_SCHEMA),
  })
  .strict();

const AIA_SCHEMA = z
  .object({
    certificate: z.array(z.string()).optional(),
    ocsp: z.array(z.string()).optional(),
  })
  .strict();

const POLICY_SCHEMA = z
  .object({
    oid: z.string().describe('A valid certificate-policy OID.'),
    cpsPointer: z.string().optional(),
    organization: z.string().optional(),
    noticeNumbers: z.array(z.number().int()).optional(),
    explicitText: z.string().optional(),
  })
  .strict();

const TEMPLATE_OVERRIDES_SCHEMA = z
  .object({
    ku: KU_SCHEMA.optional(),
    eku: EKU_SCHEMA.optional(),
    empty_extensions: z.array(z.enum(EMPTY_EXTENSION_TYPES)).optional(),
    crldps: z.array(z.string()).optional(),
    aia: AIA_SCHEMA.optional(),
    policy: z.array(POLICY_SCHEMA).optional(),
    path_len: z.number().int().optional(),
    lifetime: z
      .string()
      .optional()
      .describe('FiniteDuration string, e.g. "365 days".'),
    backdate: z
      .string()
      .optional()
      .describe('FiniteDuration string, e.g. "1 hour".'),
    check_pop: z.boolean().optional(),
    extra_csr_extensions: z.array(z.string()).optional(),
  })
  .strict()
  .optional();

const DN_ELEMENT_SCHEMA = z
  .object({
    element: z
      .string()
      .regex(
        DN_ELEMENT_RE,
        "dn element must be '<dnType>.<index>' lowercased, e.g. 'cn.1'",
      ),
    value: z.string(),
  })
  .strict();

const SAN_SCHEMA = z
  .object({
    element: z.enum(SAN_TYPES),
    values: z.array(z.string()),
  })
  .strict();

const EXTENSION_SCHEMA = z
  .object({
    type: z.enum(EXTENSION_TYPES),
    value: z.string().optional(),
  })
  .strict();

const ENROLL_INPUT = z.object({
  ca: z.string().min(1).describe('Name of a managed, enroll-enabled X509 CA.'),
  csr: z
    .string()
    .min(1)
    .describe('PKCS#10 certificate request, as a PEM string.'),
  template_name: z
    .string()
    .min(1)
    .describe('The certificate template name to enroll against.'),
  template_overrides: TEMPLATE_OVERRIDES_SCHEMA.describe(
    'Per-request template overrides (only allowed if the CA permits them).',
  ),
  dn: z
    .string()
    .optional()
    .describe(
      'RFC DN string override (wins over dn_elements if both are given).',
    ),
  dn_elements: z
    .array(DN_ELEMENT_SCHEMA)
    .optional()
    .describe(
      'Structured DN override; each element is `<dnType>.<index>` e.g. cn.1.',
    ),
  sans: z
    .array(SAN_SCHEMA)
    .optional()
    .describe('SAN override entries `{ element, values }`.'),
  extensions: z
    .array(EXTENSION_SCHEMA)
    .optional()
    .describe('Extra MS cert extensions `{ type, value? }`.'),
  ms_private_key_hash: z
    .string()
    .optional()
    .describe('Optional MS private-key hash passed through to issuance.'),
  data_from: z
    .enum(DATA_SOURCING_STRATEGIES)
    .optional()
    .describe(
      'Where DN/SAN/extension data is sourced: api (default; requires dn or ' +
        'dn_elements), csr, or apicsr.',
    ),
});

function buildEnrollPayload(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const template: Record<string, unknown> = {
    name: args['template_name'],
  };
  const ov = args['template_overrides'] as Record<string, unknown> | undefined;
  if (ov) {
    if (ov['ku'] !== undefined) template['ku'] = ov['ku'];
    if (ov['eku'] !== undefined) template['eku'] = ov['eku'];
    if (ov['empty_extensions'] !== undefined) {
      template['emptyExtensions'] = ov['empty_extensions'];
    }
    if (ov['crldps'] !== undefined) template['crldps'] = ov['crldps'];
    if (ov['aia'] !== undefined) template['aia'] = ov['aia'];
    if (ov['policy'] !== undefined) template['policy'] = ov['policy'];
    if (ov['path_len'] !== undefined) template['pathLen'] = ov['path_len'];
    if (ov['lifetime'] !== undefined) template['lifetime'] = ov['lifetime'];
    if (ov['backdate'] !== undefined) template['backdate'] = ov['backdate'];
    if (ov['check_pop'] !== undefined) template['checkPoP'] = ov['check_pop'];
    if (ov['extra_csr_extensions'] !== undefined) {
      template['extraCsrExtensions'] = ov['extra_csr_extensions'];
    }
  }

  const payload: Record<string, unknown> = {
    ca: args['ca'],
    csr: args['csr'],
    template,
  };

  if (args['dn'] !== undefined) payload['dn'] = args['dn'];
  if (args['dn_elements'] !== undefined) {
    payload['dnElements'] = args['dn_elements'];
  }
  if (args['sans'] !== undefined) payload['sans'] = args['sans'];
  if (args['extensions'] !== undefined) {
    payload['extensions'] = args['extensions'];
  }
  if (args['ms_private_key_hash'] !== undefined) {
    payload['msPrivateKeyHash'] = args['ms_private_key_hash'];
  }
  if (args['data_from'] !== undefined) payload['dataFrom'] = args['data_from'];

  return payload;
}

function registerEnroll(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'enroll_certificate',
    {
      description:
        'Enroll (issue) an X509 certificate from a PKCS#10 CSR against a ' +
        'managed CA and template. CSR-based only: the key pair is generated ' +
        'client-side and the public key is carried in the CSR. Optionally ' +
        'override DN/SAN/extensions/template fields (subject to CA policy).',
      inputSchema: ENROLL_INPUT,
    },
    async (args) => {
      // dataFrom=api requires a DN source.
      const dataFrom = args.data_from ?? 'api';
      if (dataFrom === 'api' && !args.dn && !args.dn_elements) {
        throw new StreamError(400, {
          errorCode: 'CLIENT-VALIDATION',
          message: 'data_from=api requires a DN source (dn or dn_elements).',
          remediation:
            'Provide dn or dn_elements, or set data_from to csr/apicsr to ' +
            'source the DN from the CSR.',
        });
      }

      const payload = buildEnrollPayload(args as Record<string, unknown>);
      const result = await client.post<Record<string, unknown>>(
        '/api/v1/lifecycle/enroll',
        payload,
      );
      return text(
        buildMutateResponse({
          action: 'enrolled',
          kind: 'certificate',
          name: (result?.['dn'] as string | undefined) ?? args.template_name,
          data: result ?? undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// revoke_certificate
// ---------------------------------------------------------------------------
//
// Polymorphic identification: a PEM `certificate` (wins, serial/ca ignored) OR
// a (serial + ca) pair. reason is technically optional server-side (defaults to
// unspecified) but we REQUIRE it for correct lifecycle behavior.

const REVOKE_INPUT = z.object({
  certificate: z
    .string()
    .optional()
    .describe(
      'X.509 PEM of the certificate to revoke. If given, serial/ca are ignored.',
    ),
  serial: z
    .string()
    .optional()
    .describe('Hex serial of the certificate to revoke (requires ca).'),
  ca: z.string().optional().describe('CA name (requires serial).'),
  expected_serial: z
    .string()
    .optional()
    .describe(
      'Safety confirmation for the serial+ca path: must exactly equal `serial`. ' +
        'Revocation is irreversible, so echo the serial to confirm the target. ' +
        'Not needed when revoking by `certificate` PEM (the PEM is self-identifying).',
    ),
  reason: z
    .enum(REVOCATION_REASONS)
    .describe(
      'Revocation reason (RFC string). One of: ' +
        REVOCATION_REASONS.join(', ') +
        '.',
    ),
});

function registerRevoke(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'revoke_certificate',
    {
      description:
        'Revoke an X509 certificate, identified EITHER by its PEM ' +
        '(`certificate`) OR by `serial`+`ca`. Idempotent: an already-revoked ' +
        'or expired cert returns its current state. Requires a revocation ' +
        'reason.',
      inputSchema: REVOKE_INPUT,
    },
    async (args) => {
      const hasCert = !!args.certificate;
      const hasSerial = !!args.serial;
      const hasCa = !!args.ca;

      const payload: Record<string, unknown> = { reason: args.reason };
      let name: string;

      if (hasCert) {
        payload['certificate'] = args.certificate;
        name = 'certificate (by PEM)';
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
            'Identify the certificate by `certificate` (PEM) OR by both ' +
            '`serial` and `ca`.',
          remediation: 'Pass certificate, or pass serial together with ca.',
        });
      }

      const result = await client.post<Record<string, unknown>>(
        '/api/v1/lifecycle/revoke',
        payload,
      );
      return text(
        buildMutateResponse({
          action: 'revoked',
          kind: 'certificate',
          name: (result?.['dn'] as string | undefined) ?? name,
          data: result ?? undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// list_requestable_templates
// ---------------------------------------------------------------------------
//
// GET /lifecycle/templates?permission= (204 -> []). Returns an array of
// { ca, templates: [...] }.

const LIST_TEMPLATES_INPUT = z.object({
  permission: z
    .enum(LIFECYCLE_PERMISSIONS)
    .optional()
    .describe(
      'Filter requestable templates by permission: enroll, revoke, or ' +
        'search (default search).',
    ),
});

function registerListTemplates(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'list_requestable_templates',
    {
      description:
        'List the CA/template combinations the caller may request for a given ' +
        'permission (enroll/revoke/search). Returns `{ ca, templates[] }` ' +
        'entries; empty when nothing is requestable.',
      inputSchema: LIST_TEMPLATES_INPUT,
    },
    async (args) => {
      const params = args.permission
        ? new URLSearchParams({ permission: args.permission })
        : undefined;
      const items = await client.getList<Record<string, unknown>>(
        '/api/v1/lifecycle/templates',
        params,
      );
      return text(
        buildListResponse(items, items.length, 'requestable-template'),
      );
    },
  );
}

export function registerLifecycleTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerEnroll(server, client);
  registerRevoke(server, client);
  registerListTemplates(server, client);
}
