/**
 * Crypto domain enums.
 *
 * Wire values are the exact ON-THE-WIRE strings Stream expects. Keep these as
 * the single source of truth for the crypto tools.
 */

/** Keystore type discriminator (`type`) — lowercase wire value. */
export const KEYSTORE_TYPES = [
  'software',
  'pkcs11',
  'aws',
  'akv',
  'gcp',
] as const;
export type KeystoreType = (typeof KEYSTORE_TYPES)[number];

/**
 * Key algorithm canonical wire values (key generation `description`).
 * Not every algorithm is supported by every keystore type (the server returns
 * KEY-002 for unsupported combinations — surfaced as an isError result).
 */
export const KEY_ALGORITHMS = [
  'rsa-2048',
  'rsa-3072',
  'rsa-4096',
  'rsa-8192',
  'ec-secp256r1',
  'ec-secp384r1',
  'ec-secp521r1',
  'ed-25519',
  'ed-448',
  'mldsa-44',
  'mldsa-65',
  'mldsa-87',
  'mldsa-44sha512',
  'mldsa-65sha512',
  'mldsa-87sha512',
] as const;
export type KeyAlgorithm = (typeof KEY_ALGORITHMS)[number];

/** Name validation regex shared by keystore + key names. */
export const NAME_REGEX = /^[0-9a-zA-Z\-_.]+$/;
