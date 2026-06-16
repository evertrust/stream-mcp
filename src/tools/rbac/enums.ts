/**
 * RBAC / security domain enums (on-the-wire values from docs/audit/rbac.md).
 */

/** ConfigurationPermission entryName (lowercase). */
export const CONFIGURATION_PERMISSIONS = ['audit', 'manage'] as const;

/** LifecyclePermission entryName. */
export const LIFECYCLE_PERMISSIONS = ['enroll', 'revoke', 'search'] as const;

/** CredentialsType discriminator. */
export const CREDENTIALS_TYPES = ['password', 'raw', 'ssh', 'x509'] as const;
export type CredentialsType = (typeof CREDENTIALS_TYPES)[number];

/** CredentialsTarget. */
export const CREDENTIALS_TARGETS = [
  'akv',
  'aws',
  'gcp',
  'ldap',
  'openid',
  'ssh',
  'rest',
  'stream',
] as const;
export type CredentialsTarget = (typeof CREDENTIALS_TARGETS)[number];

/**
 * Valid (type -> allowed targets) combinations. Enforced server-side; we
 * pre-validate so the model gets an actionable error instead of a 400.
 */
export const CREDENTIALS_TYPE_TARGETS: Record<
  CredentialsType,
  readonly CredentialsTarget[]
> = {
  password: ['akv', 'aws', 'ldap', 'openid', 'rest', 'ssh', 'stream'],
  raw: ['gcp', 'rest'],
  ssh: ['ssh'],
  x509: ['rest', 'stream'],
};

/** Dynamic identity provider types this domain can create/update. */
export const DYNAMIC_PROVIDER_TYPES = ['Local', 'OpenId'] as const;
export type DynamicProviderType = (typeof DYNAMIC_PROVIDER_TYPES)[number];
