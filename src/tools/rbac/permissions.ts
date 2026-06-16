/**
 * Stream permission-string grammar (shared by roles and principal infos).
 *
 * A permission is a SINGLE string. Tokens: part divider `:`, sub-part list
 * divider `,`, wildcard `*`. Comparison is case-insensitive. Validated
 * server-side against the configuration / lifecycle grammars; invalid ones
 * fail with 400 (ROLE-002 / PRINCIPAL-INFO-002). We do NOT re-validate here
 * (lifecycle CAs/templates are cross-referenced live) - we surface the grammar
 * in tool descriptions so the model builds valid strings, and let Stream be the
 * authority on validity.
 */

export const PERMISSION_GRAMMAR = [
  'Permissions are single strings. Two families:',
  '',
  'CONFIGURATION (perms = comma list of audit/manage, or *):',
  '  configuration | configuration:* | configuration:<entity2>[:<perms>]',
  '  configuration:<entity2>:<entity3>[:<perms>]',
  '  level-2 entities: security, keystore, x509, ssh, ocsp, timestamping,',
  '    notification, system, license (or *).',
  '  level-3 by parent: security->credentials,identity-provider,local-identity,',
  '    principal-info,role; x509->ca,template,eku; ssh->ca,template;',
  '    system->proxy,event,queue,configuration; timestamping->authority,ntp,signer.',
  '    keystore/ocsp/notification/license have no level-3.',
  '  e.g. configuration:*, configuration:security:role:manage,',
  '       configuration:x509:ca:audit,manage',
  '',
  'LIFECYCLE (entity = x509|ssh; cas/templates must be EXISTING names or *):',
  '  lifecycle:<entity>[:<cas>[:<templates>[:<perms>]]]',
  '  perms = comma list of enroll/revoke/search, or *.',
  '  e.g. lifecycle:x509:*:*:*, lifecycle:x509:ASA-TCA:TLS_Server:search,revoke',
  '',
  'Lifecycle CAs/templates are cross-referenced against live objects: an unknown',
  'CA or template makes the permission invalid (400). On upsert the server',
  'dedupes and sorts permissions by value.',
].join('\n');

/**
 * Map an array of permission strings to the wire shape: array of `{value}`.
 * Empty/blank strings are rejected (the server throws on blank permissions).
 */
export function toPermissionObjects(
  permissions: readonly string[] | undefined,
): Array<{ value: string }> | undefined {
  if (permissions === undefined) return undefined;
  return permissions.map((value) => ({ value }));
}
