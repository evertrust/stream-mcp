/**
 * Zod schemas + JSON-Schema doc for the polymorphic X509 Certificate Authority
 * body (managed / external). Field names are the EXACT camelCase wire names.
 *
 * Grounded in docs/audit/x509-ca.md. Managed and external field sets are
 * disjoint beyond the common trait fields; both are surfaced as an optional
 * superset on the typed `config` input and validated against type on submit.
 */
import { z } from 'zod';

import {
  ARCHIVE_CUTOFF_MODES,
  CA_TYPES,
  DURATION_RE,
  HASH_ALGORITHMS,
  OUTDATED_REVOCATION_STATUS_POLICIES,
  QC_TYPES,
} from './enums.js';

const duration = z
  .string()
  .regex(
    DURATION_RE,
    'Must be a FiniteDuration like "28 days" or "10 minutes".',
  );

// SignerPrivateKey -------------------------------------------------------------
export const signerPrivateKeySchema = z
  .object({
    keystore: z
      .string()
      .describe(
        'REQUIRED. Name of an existing keystore (cross-ref validated).',
      ),
    name: z
      .string()
      .describe(
        'REQUIRED. Private-key alias inside that keystore (must already exist).',
      ),
    hashAlgorithm: z
      .enum(HASH_ALGORITHMS)
      .optional()
      .describe(
        `Signature hash; one of ${HASH_ALGORITHMS.join(' | ')}. ` +
          'REQUIRED by the server on create for RSA keys (400 "Missing hash ' +
          'algorithm" otherwise - verified live); omit only for EC/EdDSA keys.',
      ),
    usePSS: z
      .boolean()
      .optional()
      .describe('Optional. RSA-PSS; only valid on a PKCS11 RSA key.'),
  })
  .strict();

// archiveCutoff ----------------------------------------------------------------
const archiveCutoffSchema = z
  .object({
    mode: z
      .enum(ARCHIVE_CUTOFF_MODES)
      .describe(`REQUIRED. One of ${ARCHIVE_CUTOFF_MODES.join(' | ')}.`),
    retentionPeriod: duration
      .optional()
      .describe('Required iff mode=retention; forbidden iff mode=issuer.'),
  })
  .strict();

// aia --------------------------------------------------------------------------
const aiaSchema = z
  .object({
    certificate: z
      .array(z.string())
      .optional()
      .describe('Optional. CA-issuer (CRT) URLs.'),
    ocsp: z
      .array(z.string())
      .optional()
      .describe('Optional. OCSP responder URLs.'),
  })
  .strict();

// CertificatePolicy ------------------------------------------------------------
const certificatePolicySchema = z
  .object({
    oid: z.string().describe('REQUIRED. Valid policy OID.'),
    cpsPointer: z.string().optional().describe('Optional. CPS URI.'),
    organization: z
      .string()
      .optional()
      .describe('Optional. Notice organization.'),
    noticeNumbers: z
      .array(z.number().int())
      .optional()
      .describe('Optional. User-notice numbers (default []).'),
    explicitText: z
      .string()
      .optional()
      .describe('Optional. Notice explicit text.'),
  })
  .strict();

// overridePermissions ----------------------------------------------------------
const overridePermissionsSchema = z
  .object({
    ku: z.boolean().optional().describe('Optional. Allow key-usage override.'),
    eku: z
      .boolean()
      .optional()
      .describe('Optional. Allow extended-key-usage override.'),
    emptyExtensions: z
      .boolean()
      .optional()
      .describe('Optional. Allow empty extensions.'),
    crldps: z.boolean().optional().describe('Optional. Allow CRL-DP override.'),
    aia: z.boolean().optional().describe('Optional. Allow AIA override.'),
    policy: z.boolean().optional().describe('Optional. Allow policy override.'),
    pathlen: z
      .boolean()
      .optional()
      .describe('Optional. Allow path-length override.'),
    lifetime: z
      .boolean()
      .optional()
      .describe('Optional. Allow lifetime override.'),
    backdate: z
      .boolean()
      .optional()
      .describe('Optional. Allow backdating override.'),
    checkPoP: z
      .boolean()
      .optional()
      .describe('Optional. Allow proof-of-possession check override.'),
    extraCsrExtensions: z
      .boolean()
      .optional()
      .describe('Optional. Allow extra CSR extensions.'),
  })
  .strict();

// crlPolicy --------------------------------------------------------------------
const crlPolicySchema = z
  .object({
    hardGeneration: z
      .string()
      .optional()
      .describe('Optional. Quartz cron for scheduled full regeneration.'),
    lazyGeneration: z
      .string()
      .optional()
      .describe('Optional. Quartz cron for scheduled lazy regeneration.'),
    validity: duration.describe(
      'REQUIRED. CRL validity window, e.g. "28 days".',
    ),
    eidas: z.boolean().describe('REQUIRED. eIDAS-compliant CRL (boolean).'),
  })
  .strict();

// qcStatement ------------------------------------------------------------------
const qcStatementSchema = z
  .object({
    eTSIQCCompliance: z
      .boolean()
      .describe('REQUIRED. eIDAS QC compliance flag (boolean).'),
    eTSIQCSSCD: z.boolean().describe('REQUIRED. QSCD/SSCD flag (boolean).'),
    eTSIRetentionPeriod: z
      .number()
      .int()
      .min(0)
      .describe('REQUIRED. Retention period in years (integer >= 0).'),
    eTSIQCType: z
      .enum(QC_TYPES)
      .describe(`REQUIRED. One of ${QC_TYPES.join(' | ')}.`),
    eTSIPDS: z
      .record(z.string(), z.string())
      .optional()
      .describe('Optional. PKI Disclosure Statements as lang->url map.'),
    eTSITransactionLimit: z
      .object({
        // Scala QCTransactionLimit takes Int for both (server: error.expected.int
        // on a float). currencyCode must be 3 uppercase chars (server-enforced).
        valueLimit: z
          .number()
          .int()
          .describe('REQUIRED. Limit mantissa (int).'),
        valueLimitExp: z
          .number()
          .int()
          .describe('REQUIRED. Limit exponent (int).'),
        currencyCode: z
          .string()
          .describe('REQUIRED. 3 uppercase chars, e.g. "EUR".'),
      })
      .strict()
      .optional()
      .describe('Optional. eIDAS transaction value limit.'),
    eTSILegislation: z
      .array(z.string())
      .optional()
      .describe('Optional. Country/legislation codes.'),
  })
  .strict();

// triggers (superset of managed + external trigger maps) -----------------------
const triggerNames = z
  .array(z.string())
  .optional()
  .describe('Optional. Array of existing trigger names.');

const triggersSchema = z
  .object({
    // managed
    onCRLGeneration: triggerNames.describe(
      'Optional (managed). Trigger names.',
    ),
    onCRLGenerationError: triggerNames.describe(
      'Optional (managed). Trigger names.',
    ),
    onCRLGenerationRecover: triggerNames.describe(
      'Optional (managed). Trigger names.',
    ),
    // external
    onCRLUpdate: triggerNames.describe('Optional (external). Trigger names.'),
    onCRLUpdateError: triggerNames.describe(
      'Optional (external). Trigger names.',
    ),
    onCRLUpdateRecover: triggerNames.describe(
      'Optional (external). Trigger names.',
    ),
    // shared
    onCRLSync: triggerNames.describe('Optional. Trigger names.'),
    onCRLSyncError: triggerNames.describe('Optional. Trigger names.'),
    onCRLExpiration: triggerNames.describe('Optional. Trigger names.'),
    onCAExpiration: triggerNames.describe('Optional. Trigger names.'),
  })
  .strict();

// ---------------------------------------------------------------------------
// Full polymorphic config body (typed superset). `type` + `name` mandatory.
// ---------------------------------------------------------------------------
export const caConfigSchema = z
  .object({
    type: z
      .enum(CA_TYPES)
      .describe(
        'REQUIRED. Discriminator: managed | external. Immutable. Ask the user.',
      ),
    name: z
      .string()
      .describe(
        'REQUIRED. Immutable primary key. Ask the user; never invent or infer it.',
      ),
    description: z
      .string()
      .optional()
      .describe('Optional. Free-text description.'),

    // common trait
    certificate: z
      .string()
      .optional()
      .describe(
        'PEM string. REQUIRED for external; managed: omit until issued (or supply to import a cert+key, in which case dn must be omitted).',
      ),
    trustedForClientAuthentication: z
      .boolean()
      .describe('REQUIRED (both types). No server default — boolean.'),
    trustedForServerAuthentication: z
      .boolean()
      .describe('REQUIRED (both types). No server default — boolean.'),
    compromised: z
      .boolean()
      .optional()
      .describe('Optional. Marks the CA as compromised.'),
    enableOCSP: z
      .boolean()
      .optional()
      .describe('Optional. Stripped unless VA module licensed.'),
    ocspSigner: z
      .string()
      .optional()
      .describe(
        'Optional. Existing OCSP signer name. Stripped unless VA module licensed.',
      ),
    archiveCutoff: archiveCutoffSchema
      .optional()
      .describe('Optional. Archive cutoff policy.'),
    ocspResponseMinimalDuration: duration
      .optional()
      .describe('Optional. Minimal OCSP response duration, e.g. "0 seconds".'),
    triggers: triggersSchema
      .optional()
      .describe('Optional. Trigger-name arrays (per-type keys).'),

    // managed-only
    enroll: z
      .boolean()
      .optional()
      .describe(
        'REQUIRED for managed (no default). Whether this CA can enroll end-entity certs.',
      ),
    dn: z
      .string()
      .optional()
      .describe(
        'Managed only. REQUIRED when certificate absent; MUST be omitted when certificate present. Must contain >=1 DN element (C= validated as a country code).',
      ),
    privateKey: signerPrivateKeySchema
      .optional()
      .describe('REQUIRED for managed. Keystore + key alias used to sign.'),
    altPrivateKey: signerPrivateKeySchema
      .optional()
      .describe('Optional (managed). Second key for hybrid (PQC) CAs.'),
    queue: z
      .string()
      .optional()
      .describe('Optional (managed). Existing signing queue name.'),
    enforceKeyUnicity: z
      .boolean()
      .optional()
      .describe(
        'REQUIRED for managed (no default). Reject enrollment with a duplicate public-key thumbprint.',
      ),
    crldps: z
      .array(z.string())
      .optional()
      .describe(
        'Optional (managed). CRL distribution point URLs embedded in issued certs.',
      ),
    aia: aiaSchema
      .optional()
      .describe('Optional (managed). Authority Information Access URLs.'),
    policy: z
      .array(certificatePolicySchema)
      .optional()
      .describe('Optional (managed). Certificate policies.'),
    qcStatement: qcStatementSchema
      .optional()
      .describe('Optional (managed). eIDAS QC statement.'),
    overridePermissions: overridePermissionsSchema
      .optional()
      .describe('Optional (managed). Per-field override flags.'),
    crlPolicy: crlPolicySchema
      .optional()
      .describe(
        'Optional (managed). CRL generation policy; required for generate_crl.',
      ),

    // external-only
    crlUrls: z
      .array(z.string())
      .optional()
      .describe(
        'Optional (external). CRL download URLs; each MUST start with http:// (https rejected).',
      ),
    refresh: duration
      .optional()
      .describe(
        'Optional (external). CRL re-download interval, e.g. "1 hour".',
      ),
    outdatedRevocationStatusPolicy: z
      .enum(OUTDATED_REVOCATION_STATUS_POLICIES)
      .optional()
      .describe(
        `REQUIRED for external. One of ${OUTDATED_REVOCATION_STATUS_POLICIES.join(' | ')}.`,
      ),
    timeout: duration
      .optional()
      .describe(
        'Optional (external). HTTP fetch timeout (default "5 seconds").',
      ),
    proxy: z
      .string()
      .optional()
      .describe('Optional (external). Existing HTTP proxy name.'),
  })
  .strict();

export type CaConfig = z.infer<typeof caConfigSchema>;

// ---------------------------------------------------------------------------
// JSON Schema doc surfaced by describe_ca_schema (hand-authored, audited).
// ---------------------------------------------------------------------------
export const CA_JSON_SCHEMA = {
  $comment:
    'Polymorphic CA body. `type` selects the field set; managed and external ' +
    'fields are disjoint beyond the common trait. Send certificate as a PEM ' +
    'string on write (rich object on read). revoked/revocationDate/' +
    'revocationReason/id are server-managed — never author them.',
  discriminator: 'type',
  common: {
    type: 'managed | external (required)',
    name: 'string (required, immutable primary key)',
    description: 'string (optional)',
    certificate:
      'PEM string. external: REQUIRED. managed: omit until issued, or supply to import a cert+key.',
    trustedForClientAuthentication: 'boolean (required)',
    trustedForServerAuthentication: 'boolean (required)',
    compromised: 'boolean (optional)',
    enableOCSP: 'boolean (optional; stripped unless VA module licensed)',
    ocspSigner: 'string (optional; existing OCSP signer name)',
    archiveCutoff:
      '{ mode: issuer|retention, retentionPeriod?: duration } (retentionPeriod required iff mode=retention)',
    ocspResponseMinimalDuration: 'duration string (optional)',
    triggers: 'object of trigger-name arrays (per-type keys)',
  },
  managed: {
    enroll: 'boolean (required for managed)',
    dn: 'string (mandatory when certificate absent; must be omitted when certificate present)',
    privateKey:
      '{ keystore, name, hashAlgorithm?, usePSS? } (required for managed)',
    altPrivateKey:
      '{ keystore, name, hashAlgorithm?, usePSS? } (optional; hybrid PQC)',
    queue: 'string (optional)',
    enforceKeyUnicity: 'boolean (required for managed)',
    crldps: 'string[] (optional)',
    aia: '{ certificate?: string[], ocsp?: string[] } (optional)',
    policy:
      '[{ oid, cpsPointer?, organization?, noticeNumbers?, explicitText? }] (optional)',
    qcStatement:
      '{ eTSIQCCompliance, eTSIQCSSCD, eTSIRetentionPeriod, eTSIQCType, eTSIPDS?, eTSITransactionLimit?, eTSILegislation? } (optional)',
    overridePermissions:
      '{ ku?, eku?, emptyExtensions?, crldps?, aia?, policy?, pathlen?, lifetime?, backdate?, checkPoP?, extraCsrExtensions? } (optional)',
    crlPolicy:
      '{ hardGeneration?: cron, lazyGeneration?: cron, validity: duration, eidas: boolean } (optional; required for generate_crl)',
    triggers:
      '{ onCRLGeneration?, onCRLGenerationError?, onCRLGenerationRecover?, onCRLSync?, onCRLSyncError?, onCRLExpiration?, onCAExpiration? }',
  },
  external: {
    certificate: 'PEM string (REQUIRED)',
    crlUrls: 'string[] (optional; each must start with http://)',
    refresh: 'duration string (optional)',
    outdatedRevocationStatusPolicy:
      'revoked | unknown | lastavailablestatus (required for external)',
    timeout: 'duration string (optional; default "5 seconds")',
    proxy: 'string (optional)',
    triggers:
      '{ onCRLUpdate?, onCRLUpdateError?, onCRLUpdateRecover?, onCRLSync?, onCRLSyncError?, onCRLExpiration?, onCAExpiration? }',
  },
} as const;
