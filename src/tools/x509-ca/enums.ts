/**
 * Enums for the x509-ca domain.
 * On-the-wire values are exactly what Stream parses; keep camelCase / casing intact.
 */

/** CA discriminator (`type`). */
export const CA_TYPES = ['managed', 'external'] as const;
export type CaType = (typeof CA_TYPES)[number];

/** External-only outdated revocation status policy. */
export const OUTDATED_REVOCATION_STATUS_POLICIES = [
  'revoked',
  'unknown',
  'lastavailablestatus',
] as const;

/** Hash algorithm names accepted in privateKey/altPrivateKey.hashAlgorithm. */
export const HASH_ALGORITHMS = [
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
  'SHA3-256',
  'SHA3-384',
  'SHA3-512',
] as const;

/** archiveCutoff.mode. */
export const ARCHIVE_CUTOFF_MODES = ['issuer', 'retention'] as const;

/** QC type values for qcStatement.eTSIQCType (stored/emitted uppercase). */
export const QC_TYPES = [
  'WEB',
  'ESIGN',
  'ESEAL',
  'WEB_AUTHENTICATION',
] as const;

/**
 * Duration on-the-wire regex, e.g. "28 days", "10 minutes", "0 seconds".
 */
export const DURATION_RE =
  /^([0-9]+) *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;
