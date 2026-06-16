/**
 * X509 certificate + lifecycle domain enums. Wire values are EXACTLY as the
 * server expects them.
 */

// Revocation reason - RFC wire strings (case-insensitive on input). The server
// accepts only these 7. Default when omitted = `unspecified`.
export const REVOCATION_REASONS = [
  'unspecified',
  'keyCompromise',
  'cACompromise',
  'affiliationChanged',
  'superseded',
  'cessationOfOperation',
  'certificateHold',
] as const;
export type RevocationReason = (typeof REVOCATION_REASONS)[number];

// Sort order for search sortedBy[].order (only Asc/KeyAsc => ascending).
export const SORT_ORDERS = ['Asc', 'Desc', 'KeyAsc', 'KeyDesc'] as const;

// Operator for aggregate having.operator.
export const HAVING_OPERATORS = ['gt', 'gte', 'lt', 'lte', 'eq', 'ne'] as const;

// Lifecycle permission for GET /lifecycle/templates?permission= (default search).
export const LIFECYCLE_PERMISSIONS = ['enroll', 'revoke', 'search'] as const;

// Data sourcing strategy for enroll dataFrom (default api).
export const DATA_SOURCING_STRATEGIES = ['api', 'csr', 'apicsr'] as const;

// SAN type for enroll sans[].element.
export const SAN_TYPES = [
  'rfc822name',
  'dnsname',
  'uri',
  'ipaddress',
  'othername_upn',
  'othername_guid',
  'registered_id',
] as const;

// Extension type for enroll extensions[].type (MS-only).
export const EXTENSION_TYPES = [
  'ms_sid',
  'ms_template',
  'ms_template_v2',
] as const;

// Key usage for enroll template.ku.values[].
export const KEY_USAGE_ELEMENTS = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
] as const;

// SCQL searchable + sort/projection fields (certificate search result fields).
export const SEARCH_FIELDS = [
  'id',
  'ca',
  'template',
  'certificate',
  'dn',
  'serial',
  'issuer',
  'notBefore',
  'notAfter',
  'publicKeyThumbprint',
  'revoked',
  'revocationDate',
  'revocationReason',
  'permissions',
] as const;

// Valid elements for aggregate groupBy[].
export const GROUP_BY_ELEMENTS = [
  'expired',
  'issuer',
  'template',
  'notAfter.day',
  'notAfter.month',
  'notAfter.year',
  'notBefore.day',
  'notBefore.month',
  'notBefore.year',
  'profile',
  'revocationDate.day',
  'revocationDate.month',
  'revocationDate.year',
  'revocationReason',
  'revoked',
  'status',
] as const;
