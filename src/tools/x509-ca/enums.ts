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

/**
 * Hash algorithm names accepted in privateKey/altPrivateKey.hashAlgorithm.
 * The server matches the exact name (no normalization) and returns the same
 * form, so the SHA-3 values use UNDERSCORES (SHA3_256), not hyphens
 * (SHA3-512 is rejected; SHA3_512 round-trips).
 */
export const HASH_ALGORITHMS = [
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
  'SHA3_224',
  'SHA3_256',
  'SHA3_384',
  'SHA3_512',
] as const;

/** archiveCutoff.mode. */
export const ARCHIVE_CUTOFF_MODES = ['issuer', 'retention'] as const;

/**
 * QC type values for qcStatement.eTSIQCType (stored/emitted uppercase).
 * The server accepts exactly these four values (WEB, ESIGN, ESEAL, NONE):
 * `WEB_AUTHENTICATION` is rejected.
 */
export const QC_TYPES = ['WEB', 'ESIGN', 'ESEAL', 'NONE'] as const;

/**
 * Duration on-the-wire regex, e.g. "28 days", "10 minutes", "0 seconds".
 */
export const DURATION_RE =
  /^([0-9]+) *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;
