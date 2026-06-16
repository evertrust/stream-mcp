/**
 * SSH domain enums.
 * Wire values are EXACTLY as the server expects them (case-sensitive).
 */

// SSH certificate type — on-the-wire UPPERCASE strings.
export const SSH_CERTIFICATE_TYPES = ['USER', 'HOST'] as const;

// Hash algorithm — private key hashAlgorithm. In practice SSH CAs use
// SHA256/SHA384/SHA512; EdDSA keys omit it.
export const SSH_HASH_ALGORITHMS = [
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

// authorizedKeyTypes whitelist (SSHCertificateTemplate.availableKeyTypes).
export const SSH_AUTHORIZED_KEY_TYPES = [
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'ssh-ed25519',
] as const;

// Lifecycle permission for GET /lifecycle/templates?permission= (default search).
export const SSH_LIFECYCLE_PERMISSIONS = [
  'enroll',
  'revoke',
  'search',
] as const;

// Sort order for search sortedBy[].order and aggregate sortOrder.
export const SSH_SORT_ORDERS = ['Asc', 'Desc', 'KeyAsc', 'KeyDesc'] as const;

// Operator for aggregate having.operator (lowercase wire value).
export const SSH_HAVING_OPERATORS = [
  'gt',
  'gte',
  'lt',
  'lte',
  'eq',
  'ne',
] as const;

// SSH certificate search valid fields (fields + sortedBy[].element).
export const SSH_SEARCH_FIELDS = [
  'ca',
  'certificate',
  'id',
  'keyId',
  'permissions',
  'publicKeyThumbprint',
  'revocationDate',
  'revoked',
  'serial',
  'template',
  'type',
  'validAfter',
  'validBefore',
] as const;

// Valid elements for aggregate groupBy[].
export const SSH_GROUP_BY_ELEMENTS = [
  'expired',
  'template',
  'type',
  'validAfter.day',
  'validAfter.month',
  'validAfter.year',
  'validBefore.day',
  'validBefore.month',
  'validBefore.year',
  'profile',
  'revocationDate.day',
  'revocationDate.month',
  'revocationDate.year',
  'revocationReason',
  'revoked',
  'status',
] as const;
