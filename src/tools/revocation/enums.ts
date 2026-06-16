/**
 * Revocation-domain enums.
 */

/** Hash algorithm values used for an OCSP signer's private key. */
export const HASH_ALGORITHMS = [
  'SHA1',
  'SHA224',
  'SHA256',
  'SHA384',
  'SHA512',
] as const;
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

/** CA `type`, surfaced on a CRL info object. */
export const CA_TYPES = ['managed', 'external'] as const;
export type CaType = (typeof CA_TYPES)[number];
