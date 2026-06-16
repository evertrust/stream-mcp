/**
 * Enums for the x509-ca domain (live-verified against docs/audit/x509-ca.md).
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
 * CFHashAlgorithm names accepted in privateKey/altPrivateKey.hashAlgorithm.
 * The server parses with `CFHashAlgorithm.valueOf(name)` (no normalization) and
 * writes `.toString`, so the SHA-3 constants use UNDERSCORES (SHA3_256), not
 * hyphens — verified against certfactory-2.5.12 and live (SHA3-512 is rejected:
 * "No enum constant ...CFHashAlgorithm.SHA3-512"; SHA3_512 round-trips).
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
 * CFQCType values for qcStatement.eTSIQCType (stored/emitted uppercase).
 * The CertFactory `CFQCType` enum has exactly these four constants
 * (WEB, ESIGN, ESEAL, NONE) — verified against certfactory-2.5.12 and live:
 * `WEB_AUTHENTICATION` is rejected by the server ("No enum constant ...CFQCType.WEB_AUTHENTICATION").
 */
export const QC_TYPES = ['WEB', 'ESIGN', 'ESEAL', 'NONE'] as const;

/**
 * FiniteDuration on-the-wire regex (Scala Duration.toString form),
 * e.g. "28 days", "10 minutes", "0 seconds".
 */
export const DURATION_RE =
  /^([0-9]+) *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;
