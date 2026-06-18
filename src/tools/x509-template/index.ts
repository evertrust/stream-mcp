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
  kuSchema,
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
      '`lifetime` (FiniteDuration like "365d"). `ku` (Key Usage) is required and ' +
      'must define at least one value. Fails if the name already exists.\n' +
      'KEEP TEMPLATES GENERAL — INHERIT FROM THE CA: a template has no `ca`, so ' +
      'one template is reused across CAs. PREFER crldps_from_ca=true and ' +
      'aia_from_ca=true (and usually policy_from_ca=true) so each issued cert ' +
      'inherits the CRL Distribution Point and AIA (including the OCSP responder ' +
      'URL) from whichever CA issues it. Configure those once on the CA (its ' +
      'crldps, aia.ocsp, ocspSigner via create_ca/update_ca), then create ONE ' +
      'broad template that serves every CA. Do NOT create a template per CA, and ' +
      'do NOT restate CRL/AIA/OCSP URLs across multiple templates — there is no ' +
      'separate "OCSP signer template". Set a *_from_ca flag to false with an ' +
      'explicit crldps/aia only to deliberately OVERRIDE that CA value. Create a ' +
      'new template only for a genuine policy difference (key usage, EKU, ' +
      'lifetime, subject/SAN constraints). See stream://knowledge/templates.',
    mandatoryFields: [
      'name',
      'lifetime',
      'enabled',
      'crldps_from_ca',
      'aia_from_ca',
      'policy_from_ca',
      'qc_statement_from_ca',
      'ku',
    ],
    inputSchema: z.object({
      ...templateMandatoryShape,
      ...templateOptionalShape,
      // `ku` is Option in the model but the server's validateKu requires at
      // least one KU value across the template; a template with no `ku` at all
      // fails. So `ku` is effectively mandatory on create (see audit line 68).
      // This override (after the optional shape) makes it a required param.
      ku: kuSchema.describe(
        'Required. Key Usage (ku). At least one KU value must be defined ' +
          '(a template with no ku, or with an empty values list, is rejected ' +
          'by the server). Ask the user which key usages this template needs.',
      ),
    }),
    preValidate: (args) => {
      const ku = (args as { ku?: { values?: unknown[] } }).ku;
      if (!ku || !Array.isArray(ku.values) || ku.values.length === 0) {
        return (
          'You must supply ku with at least one Key Usage value. The server ' +
          'rejects a template that defines no Key Usage. Ask the user which ' +
          'key usages this template needs (e.g. digitalSignature, ' +
          'keyEncipherment, keyCertSign).'
        );
      }
      return undefined;
    },
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
