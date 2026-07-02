/**
 * Trigger / notification enums — wire entryNames, exactly as Stream 2.1 expects.
 * Source: docs/audit/triggers.md "Enums".
 */

/** Top-level discriminator `type`. */
export const TRIGGER_TYPES = ['email', 'rest', 'external_rl_storage'] as const;
export type TriggerType = (typeof TRIGGER_TYPES)[number];

/**
 * Trigger types this domain's create/update/test tools support. EXTERNAL_RL_STORAGE
 * is the same polymorphic root but owned by the RL-storage domain.
 */
export const NOTIFICATION_TYPES = ['email', 'rest'] as const;
export type NotificationType = (typeof NOTIFICATION_TYPES)[number];

/** TriggerEvent `event` wire entryNames. */
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
export type TriggerEvent = (typeof TRIGGER_EVENTS)[number];

/**
 * Events that REQUIRE `runPeriod`. All other events FORBID `runPeriod`.
 * Source: docs/audit/triggers.md.
 */
export const RUN_PERIOD_EVENTS = new Set<string>([
  'on_crl_expiration',
  'on_x509_ca_expiration',
  'on_ocsp_signer_expiration',
  'on_tsa_signer_expiration',
  'on_credentials_expiration',
  'on_license_expiration',
  // NB: the deprecated alias `on_ca_expiration` is deliberately NOT here -
  // Stream itself rejects runPeriod on it (verified live: 400 TRIGGER-002
  // "runPeriod cannot be specified on event 'on_ca_expiration'"). Use
  // on_x509_ca_expiration for a periodic CA-expiration trigger.
]);

/** RESTAuthenticationType `authenticationType`. */
export const REST_AUTH_TYPES = [
  'basic',
  'bearer',
  'custom',
  'noauth',
  'x509',
] as const;
export type RestAuthType = (typeof REST_AUTH_TYPES)[number];

/** RESTMethod `method` (uppercase). */
export const REST_METHODS = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'HEAD',
  'DELETE',
] as const;
export type RestMethod = (typeof REST_METHODS)[number];

/** RESTPayloadType `payloadType`. */
export const REST_PAYLOAD_TYPES = ['json', 'text'] as const;
export type RestPayloadType = (typeof REST_PAYLOAD_TYPES)[number];
