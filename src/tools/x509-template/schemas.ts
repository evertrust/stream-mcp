/**
 * Zod input schemas + wire payload builder for X509 certificate templates.
 *
 * Tool inputs are snake_case at the top level; nested object keys already match
 * the camelCase wire field names (e.g. eTSIQCCompliance) and are passed through
 * verbatim. buildTemplatePayload() maps the snake_case top-level inputs to the
 * exact camelCase wire fields from docs/audit/x509-template.md and drops any
 * undefined optional so omitted fields are simply absent from the body.
 */
import { z } from 'zod';

import {
  DN_ELEMENT_VALUES,
  EMPTY_EXTENSION_VALUES,
  EXTENSION_TYPE_VALUES,
  KEY_USAGE_VALUES,
  QC_TYPE_VALUES,
  SAN_TYPE_VALUES,
} from './enums.js';

// ---------------------------------------------------------------------------
// FiniteDuration (lifetime, backdate)
// ---------------------------------------------------------------------------

// Input accepts compact ("365d") or spaced ("365 days"); output is the human
// canonical form ("365 days"). We accept either form on input.
const DURATION_RE =
  /^[0-9]+ *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;

const durationSchema = z
  .string()
  .regex(
    DURATION_RE,
    'FiniteDuration like "365d" / "365 days" / "20m" / "5 minutes".',
  );

// ---------------------------------------------------------------------------
// Nested object schemas
// ---------------------------------------------------------------------------

export const kuSchema = z
  .object({
    critical: z.boolean().describe('Mark the Key Usage extension critical.'),
    values: z
      .array(z.enum(KEY_USAGE_VALUES))
      .describe('Key Usage values. At least one KU must be defined.'),
  })
  .describe(
    'Key Usage (ku). At least one KU value must exist on the template.',
  );

export const ekuValueSchema = z.object({
  name: z.string().describe('EKU name (e.g. serverAuth).'),
  oid: z.string().describe('EKU OID (must be a valid OID).'),
  custom: z
    .boolean()
    .default(false)
    .describe(
      'true for a custom EKU; custom EKU names must already exist at ' +
        '/api/v1/extension/ekus. The server REQUIRES this field on every eku ' +
        'value (it 400s with "/eku/values(n)/custom: error.path.missing" if ' +
        'absent), so it defaults to false and is always sent.',
    ),
});

export const ekuSchema = z
  .object({
    critical: z.boolean(),
    values: z.array(ekuValueSchema),
  })
  .describe(
    'Extended Key Usage (eku). Non-built-in EKUs must reference an existing Custom EKU by name.',
  );

export const aiaSchema = z
  .object({
    certificate: z.array(z.string()).optional().describe('caIssuers URLs.'),
    ocsp: z.array(z.string()).optional().describe('OCSP responder URLs.'),
  })
  .describe('Authority Information Access (aia).');

export const policyElementSchema = z.object({
  oid: z.string().describe('Policy OID (must be a valid OID).'),
  cpsPointer: z.string().optional(),
  organization: z.string().optional(),
  noticeNumbers: z.array(z.number().int()).optional().describe('Default [].'),
  explicitText: z.string().optional(),
});

export const qcTransactionLimitSchema = z.object({
  valueLimit: z.number().int(),
  valueLimitExp: z.number().int(),
  currencyCode: z
    .string()
    .length(3)
    .describe('Exactly 3 uppercase chars (e.g. EUR).'),
});

export const qcStatementSchema = z
  .object({
    eTSIQCCompliance: z.boolean(),
    eTSIQCSSCD: z.boolean(),
    eTSIRetentionPeriod: z.number().int().min(0),
    eTSIQCType: z.enum(QC_TYPE_VALUES),
    eTSIPDS: z
      .record(z.string(), z.string())
      .optional()
      .describe('Optional map of language -> URL.'),
    eTSITransactionLimit: qcTransactionLimitSchema.optional(),
    eTSILegislation: z.array(z.string()).optional(),
  })
  .describe('eIDAS QC statement (qcStatement).');

export const privateKeyUsagePeriodSchema = z
  .object({
    notBefore: z
      .string()
      .describe('ISO-8601 instant, e.g. 2026-01-01T00:00:00Z.'),
    notAfter: z
      .string()
      .describe('ISO-8601 instant; must be strictly after notBefore.'),
  })
  .describe('Private Key Usage Period (privateKeyUsagePeriod).');

export const dnElementSchema = z.object({
  type: z.enum(DN_ELEMENT_VALUES).describe('DN element type.'),
  mandatory: z.boolean(),
  editable: z.boolean(),
  value: z
    .string()
    .optional()
    .describe('Default/templated value (required when not editable).'),
  regex: z
    .string()
    .optional()
    .describe('Validation regex (must start with ^ and end with $).'),
  whitelist: z
    .array(z.string())
    .optional()
    .describe('Allowed values (cannot be combined with regex).'),
});

export const sanElementSchema = z.object({
  type: z.enum(SAN_TYPE_VALUES).describe('SAN element type.'),
  min: z.number().int().min(0).optional(),
  max: z.number().int().min(0).optional(),
  regex: z
    .string()
    .optional()
    .describe('Validation regex (must start with ^ and end with $).'),
});

export const extensionElementSchema = z.object({
  type: z.enum(EXTENSION_TYPE_VALUES).describe('Microsoft extension type.'),
  value: z.string().optional().describe('ms_sid must NOT carry a value.'),
  mandatory: z.boolean(),
  editable: z.boolean(),
});

// ---------------------------------------------------------------------------
// Top-level template input shape (snake_case) — shared by create + update
// ---------------------------------------------------------------------------

/** Optional template fields, snake_case input -> camelCase wire. */
export const templateOptionalShape = {
  ku: kuSchema.optional(),
  eku: ekuSchema.optional(),
  empty_extensions: z
    .array(z.enum(EMPTY_EXTENSION_VALUES))
    .optional()
    .describe('emptyExtensions: e.g. ["no_revocation_check"].'),
  crldps: z
    .array(z.string())
    .optional()
    .describe('CRL Distribution Point URLs.'),
  aia: aiaSchema.optional(),
  policy: z
    .array(policyElementSchema)
    .optional()
    .describe('Certificate Policies.'),
  path_len: z
    .number()
    .int()
    .optional()
    .describe('pathLen: BasicConstraints pathLenConstraint.'),
  backdate: durationSchema
    .optional()
    .describe('notBefore backdating FiniteDuration (e.g. "5 minutes").'),
  check_pop: z
    .boolean()
    .optional()
    .describe('checkPoP: verify CSR Proof-of-Possession (effective true).'),
  qc_statement: qcStatementSchema.optional(),
  private_key_usage_period: privateKeyUsagePeriodSchema.optional(),
  subject: z
    .array(dnElementSchema)
    .optional()
    .describe('DN constraints. If present must be non-empty.'),
  sans: z.array(sanElementSchema).optional().describe('SAN constraints.'),
  extensions: z
    .array(extensionElementSchema)
    .optional()
    .describe('Microsoft extension elements (no duplicate type).'),
  remove_basic_constraints: z
    .boolean()
    .optional()
    .describe(
      'removeBasicConstraints: cannot be true if ku includes keyCertSign.',
    ),
  extra_csr_extensions: z
    .array(z.string())
    .optional()
    .describe('extraCsrExtensions: OIDs of CSR extensions to copy verbatim.'),
} as const;

/** Mandatory template fields, snake_case input -> camelCase wire. */
export const templateMandatoryShape = {
  name: z
    .string()
    .regex(
      /^[0-9a-zA-Z\-_.]+$/,
      'Immutable key; allowed chars: alphanumerics, -, _, .',
    )
    .describe('Immutable unique template name (primary key).'),
  lifetime: durationSchema.describe(
    'Mandatory certificate validity FiniteDuration (e.g. "365d").',
  ),
  enabled: z
    .boolean()
    .describe('Whether the template is enabled (disabled = not requestable).'),
  crldps_from_ca: z
    .boolean()
    .describe('crldpsFromCA: inherit CRL DPs from the issuing CA.'),
  aia_from_ca: z
    .boolean()
    .describe('aiaFromCA: inherit AIA from the issuing CA.'),
  policy_from_ca: z
    .boolean()
    .describe(
      'policyFromCA: inherit certificate policies from the issuing CA.',
    ),
  qc_statement_from_ca: z
    .boolean()
    .describe('qcStatementFromCA: inherit QC statement from the issuing CA.'),
} as const;

// ---------------------------------------------------------------------------
// Wire payload builder (snake_case input -> camelCase wire body)
// ---------------------------------------------------------------------------

const SNAKE_TO_WIRE: Record<string, string> = {
  empty_extensions: 'emptyExtensions',
  crldps_from_ca: 'crldpsFromCA',
  aia_from_ca: 'aiaFromCA',
  policy_from_ca: 'policyFromCA',
  path_len: 'pathLen',
  check_pop: 'checkPoP',
  qc_statement: 'qcStatement',
  qc_statement_from_ca: 'qcStatementFromCA',
  private_key_usage_period: 'privateKeyUsagePeriod',
  remove_basic_constraints: 'removeBasicConstraints',
  extra_csr_extensions: 'extraCsrExtensions',
};

// Keys whose name is identical in snake-input and on the wire.
const PASSTHROUGH = new Set([
  'name',
  'ku',
  'eku',
  'crldps',
  'aia',
  'policy',
  'lifetime',
  'backdate',
  'subject',
  'sans',
  'extensions',
  'enabled',
]);

/**
 * Map a parsed template input object to the exact camelCase wire body,
 * dropping undefined optionals (so omitted fields are absent).
 */
export function buildTemplatePayload(
  args: Record<string, unknown>,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args)) {
    if (value === undefined) continue;
    if (PASSTHROUGH.has(key)) {
      body[key] = value;
      continue;
    }
    const wire = SNAKE_TO_WIRE[key];
    if (wire) body[wire] = value;
    // keys not in either map (e.g. clear_fields) are handled by the caller.
  }
  return body;
}
