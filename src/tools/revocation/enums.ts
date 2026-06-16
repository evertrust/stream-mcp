/**
 * Revocation-domain enums, grounded in docs/audit/revocation.md.
 */

/** CFHashAlgorithm values used for an OCSP signer's private key. */
export const HASH_ALGORITHMS = [
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
] as const;
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

/** X509CertificateAuthorityType, surfaced on a CRLInfo. */
export const CA_TYPES = ['managed', 'external'] as const;
export type CaType = (typeof CA_TYPES)[number];
