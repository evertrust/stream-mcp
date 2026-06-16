/**
 * TSA-domain enums.
 */

/**
 * Hash algorithm wire values. Used by the authority acceptedHashAlgorithms
 * and the signer privateKey.hashAlgorithm.
 * NOTE: wire form uses the underscore enum name (`SHA3_256`), NOT the
 * BouncyCastle hyphen value (`SHA3-256`).
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
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];
