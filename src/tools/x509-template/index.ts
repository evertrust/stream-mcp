/**
 * X509 certificate template (profile) domain — standard name-keyed CRUD.
 *
 * Tools: list_templates, get_template, create_template, update_template,
 * delete_template. Routes mounted at /api/v1/templates. Contract:
 * docs/audit/x509-template.md.
 *
 * Quirks honored:
 *  - PUT-on-collection-root full-replace keyed by body `name` (putOnCollection).
 *  - list 204 -> [] (scaffold uses client.getList).
 *  - `id` is server-managed -> stripFields ['id']; never sent.
 *  - `name` immutable; `lifetime` mandatory; FiniteDuration accepts "365d".
 *  - DELETE blocked while a valid certificate references the template
 *    (CERTIFICATE-TEMPLATE-005).
 *  - No secrets/write-only fields; all fields round-trip.
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
import {
  buildTemplatePayload,
  templateMandatoryShape,
  templateOptionalShape,
} from './schemas.js';

const SPEC: ConfigSpec = {
  noun: 'template',
  nounPlural: 'templates',
  label: 'X509 certificate template',
  routeCollection: '/api/v1/templates',
  routeItem: '/api/v1/templates/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  // `id` is the only server-managed field (generated on POST, preserved on PUT).
  // Everything else round-trips (FiniteDuration / eku.custom read back richer
  // but are accepted verbatim on PUT).
  stripFields: ['id'],
  putOnCollection: true,
  knowledgeRef: 'docs/audit/x509-template.md',
};

export function registerX509TemplateTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List X509 certificate templates (profiles) sorted by name. Returns the ' +
      'full template body for each.',
    getDescription:
      'Get a single X509 certificate template by name (disabled templates are ' +
      'returned too).',
  });

  registerCreateTool(server, client, SPEC, {
    description:
      'Create an X509 certificate template (profile). Body is the full template. ' +
      'Note: a template has NO ca / keyType / signatureHashAlgorithm; validity is ' +
      '`lifetime` (FiniteDuration like "365d"). At least one Key Usage value must ' +
      'be defined. Fails if the name already exists.',
    mandatoryFields: [
      'name',
      'lifetime',
      'enabled',
      'crldps_from_ca',
      'aia_from_ca',
      'policy_from_ca',
      'qc_statement_from_ca',
    ],
    inputSchema: z.object({
      ...templateMandatoryShape,
      ...templateOptionalShape,
    }),
    buildPayload: (args) => buildTemplatePayload(args),
  });

  registerUpdateTool(server, client, SPEC, {
    description:
      'Update an X509 certificate template by name (PUT full-replace keyed by ' +
      'body name). GET -> strip id -> merge supplied fields -> PUT. Omitted ' +
      'OPTIONAL fields are preserved from the current record (merge), but note ' +
      'the server itself performs a full replace, so the merge resends all ' +
      'existing fields. Use clear_fields to null an optional field.',
    inputSchema: z.object({
      name: templateMandatoryShape.name,
      // All write fields optional on update (merged over the current record).
      lifetime: templateMandatoryShape.lifetime.optional(),
      enabled: templateMandatoryShape.enabled.optional(),
      crldps_from_ca: templateMandatoryShape.crldps_from_ca.optional(),
      aia_from_ca: templateMandatoryShape.aia_from_ca.optional(),
      policy_from_ca: templateMandatoryShape.policy_from_ca.optional(),
      qc_statement_from_ca:
        templateMandatoryShape.qc_statement_from_ca.optional(),
      ...templateOptionalShape,
      clear_fields: z
        .array(z.string())
        .optional()
        .describe(
          'Optional wire field names to null (e.g. ["aia","subject"]). ' +
            'Cannot target id or name.',
        ),
    }),
    buildOverrides: (args) => {
      // Strip name (it is the lookup key, preserved by the merge) + clear_fields
      // (handled by the scaffold) before mapping to wire fields.
      const { name: _name, clear_fields: _clear, ...rest } = args;
      return buildTemplatePayload(rest);
    },
  });

  registerDeleteTool(server, client, SPEC, {
    description: 'Delete an X509 certificate template by name.',
    deleteConstraints:
      'Blocked (CERTIFICATE-TEMPLATE-005) while any valid (non-expired, ' +
      'non-revoked) certificate was issued under this template. On success the ' +
      'server cascades cleanup into Role and PrincipalInfo references.',
  });
}
