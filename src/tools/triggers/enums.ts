/**
 * Trigger / notification enums - wire values, exactly as Stream 2.1 expects.
 */

/** Top-level discriminator `type`. */
export const TRIGGER_TYPES = ['email', 'rest', 'external_rl_storage'] as const;
export type TriggerKind = (typeof TRIGGER_TYPES)[number];

/**
 * Trigger types this domain's create/update/test tools support.
 * `external_rl_storage` shares the polymorphic root but is not supported by
 * these tools.
 */
export const NOTIFICATION_TYPES = ['email', 'rest'] as const;
export type NotificationType = (typeof NOTIFICATION_TYPES)[number];

/** Trigger `event` wire values. */
export const TRIGGER_EVENTS = [
  // CRL
  'on_crl_gen',
  'on_crl_gen_error',
  'on_crl_gen_recover',
  'on_crl_update',
  'on_crl_update_error',
  'on_crl_update_recover',
  'on_crl_sync',
  'on_crl_sync_error',
  'on_crl_expiration',
  // KRL
  'on_krl_gen',
  'on_krl_gen_error',
  'on_krl_gen_recover',
  'on_krl_sync',
  'on_krl_sync_error',
  // Expiration
  'on_x509_ca_expiration',
  'on_ocsp_signer_expiration',
  'on_tsa_signer_expiration',
  'on_credentials_expiration',
  'on_license_expiration',
  // Error
  'on_trigger_error',
  // Deprecated (still accepted)
  'on_ca_expiration',
] as const;
export type TriggerEventName = (typeof TRIGGER_EVENTS)[number];

/**
 * Events that REQUIRE `runPeriod`. All other events FORBID `runPeriod`.
 */
export const RUN_PERIOD_EVENTS = new Set<string>([
  'on_crl_expiration',
  'on_x509_ca_expiration',
  'on_ocsp_signer_expiration',
  'on_tsa_signer_expiration',
  'on_credentials_expiration',
  'on_license_expiration',
]);

/** REST `authenticationType`. */
export const REST_AUTH_TYPES = [
  'basic',
  'bearer',
  'custom',
  'noauth',
  'x509',
] as const;
export type RestAuthType = (typeof REST_AUTH_TYPES)[number];

/** REST `method` (uppercase). */
export const REST_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'HEAD',
  'DELETE',
] as const;
export type RestMethod = (typeof REST_METHODS)[number];

/** REST `payloadType`. */
export const REST_PAYLOAD_TYPES = ['json', 'text'] as const;
export type RestPayloadType = (typeof REST_PAYLOAD_TYPES)[number];
