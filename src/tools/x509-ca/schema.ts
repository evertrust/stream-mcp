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
    keystore: z.string().describe('Name of an existing keystore.'),
    name: z.string().describe('Private-key alias inside that keystore.'),
    hashAlgorithm: z
      .enum(HASH_ALGORITHMS)
      .optional()
      .describe('Omit for EC/EdDSA keys.'),
    usePSS: z
      .boolean()
      .optional()
      .describe('RSA-PSS; only valid on a PKCS11 RSA key.'),
  })
  .strict();

// archiveCutoff ----------------------------------------------------------------
const archiveCutoffSchema = z
  .object({
    mode: z.enum(ARCHIVE_CUTOFF_MODES),
    retentionPeriod: duration
      .optional()
      .describe('Required iff mode=retention; forbidden iff mode=issuer.'),
  })
  .strict();

// aia --------------------------------------------------------------------------
const aiaSchema = z
  .object({
    certificate: z.array(z.string()).optional(),
    ocsp: z.array(z.string()).optional(),
  })
  .strict();

// CertificatePolicy ------------------------------------------------------------
const certificatePolicySchema = z
  .object({
    oid: z.string().describe('Valid OID.'),
    cpsPointer: z.string().optional(),
    organization: z.string().optional(),
    noticeNumbers: z.array(z.number().int()).optional(),
    explicitText: z.string().optional(),
  })
  .strict();

// overridePermissions ----------------------------------------------------------
const overridePermissionsSchema = z
  .object({
    ku: z.boolean().optional(),
    eku: z.boolean().optional(),
    emptyExtensions: z.boolean().optional(),
    crldps: z.boolean().optional(),
    aia: z.boolean().optional(),
    policy: z.boolean().optional(),
    pathlen: z.boolean().optional(),
    lifetime: z.boolean().optional(),
    backdate: z.boolean().optional(),
    checkPoP: z.boolean().optional(),
    extraCsrExtensions: z.boolean().optional(),
  })
  .strict();

// crlPolicy --------------------------------------------------------------------
const crlPolicySchema = z
  .object({
    hardGeneration: z.string().optional().describe('Quartz cron string.'),
    lazyGeneration: z.string().optional().describe('Quartz cron string.'),
    validity: duration.describe('CRL validity window, e.g. "28 days".'),
    eidas: z.boolean(),
  })
  .strict();

// qcStatement ------------------------------------------------------------------
const qcStatementSchema = z
  .object({
    eTSIQCCompliance: z.boolean(),
    eTSIQCSSCD: z.boolean(),
    eTSIRetentionPeriod: z.number().int().min(0),
    eTSIQCType: z.enum(QC_TYPES),
    eTSIPDS: z.record(z.string(), z.string()).optional(),
    eTSITransactionLimit: z
      .object({
        valueLimit: z.number(),
        valueLimitExp: z.number().int(),
        currencyCode: z.string(),
      })
      .strict()
      .optional(),
    eTSILegislation: z.array(z.string()).optional(),
  })
  .strict();

// triggers (superset of managed + external trigger maps) -----------------------
const triggersSchema = z
  .object({
    // managed
    onCRLGeneration: z.array(z.string()).optional(),
    onCRLGenerationError: z.array(z.string()).optional(),
    onCRLGenerationRecover: z.array(z.string()).optional(),
    // external
    onCRLUpdate: z.array(z.string()).optional(),
    onCRLUpdateError: z.array(z.string()).optional(),
    onCRLUpdateRecover: z.array(z.string()).optional(),
    // shared
    onCRLSync: z.array(z.string()).optional(),
    onCRLSyncError: z.array(z.string()).optional(),
    onCRLExpiration: z.array(z.string()).optional(),
    onCAExpiration: z.array(z.string()).optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Full polymorphic config body (typed superset). `type` + `name` mandatory.
// ---------------------------------------------------------------------------
export const caConfigSchema = z
  .object({
    type: z.enum(CA_TYPES).describe('Discriminator: managed | external.'),
    name: z.string().describe('Immutable primary key.'),
    description: z.string().optional(),

    // common trait
    certificate: z
      .string()
      .optional()
      .describe(
        'PEM string. MANDATORY for external; managed: omit until issued (or supply to import).',
      ),
    trustedForClientAuthentication: z.boolean(),
    trustedForServerAuthentication: z.boolean(),
    compromised: z.boolean().optional(),
    enableOCSP: z
      .boolean()
      .optional()
      .describe('Stripped unless VA module licensed.'),
    ocspSigner: z.string().optional().describe('Existing OCSP signer name.'),
    archiveCutoff: archiveCutoffSchema.optional(),
    ocspResponseMinimalDuration: duration.optional(),
    triggers: triggersSchema.optional(),

    // managed-only
    enroll: z.boolean().optional(),
    dn: z
      .string()
      .optional()
      .describe(
        'Subject DN; mandatory when certificate absent, forbidden when present.',
      ),
    privateKey: signerPrivateKeySchema.optional(),
    altPrivateKey: signerPrivateKeySchema.optional(),
    queue: z.string().optional(),
    enforceKeyUnicity: z.boolean().optional(),
    crldps: z.array(z.string()).optional(),
    aia: aiaSchema.optional(),
    policy: z.array(certificatePolicySchema).optional(),
    qcStatement: qcStatementSchema.optional(),
    overridePermissions: overridePermissionsSchema.optional(),
    crlPolicy: crlPolicySchema.optional(),

    // external-only
    crlUrls: z
      .array(z.string())
      .optional()
      .describe('CRL download URLs; each must start with http://.'),
    refresh: duration.optional(),
    outdatedRevocationStatusPolicy: z
      .enum(OUTDATED_REVOCATION_STATUS_POLICIES)
      .optional(),
    timeout: duration.optional(),
    proxy: z.string().optional(),
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
