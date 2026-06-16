/**
 * System domain enums.
 *
 * Only the wire-side enums the MCP tools actually validate/emit live here.
 * Dictionary lists (key types / DN elements / SAN types) are intentionally
 * fetched live from Stream rather than hard-coded, since they are
 * license/version-dependent.
 */

/**
 * System configuration `type` — the `:type` path param and the `type` body
 * discriminator for system configuration entries.
 */
export const SYSTEM_CONFIGURATION_TYPES = [
  'license',
  'internal_monitor',
] as const;

export type SystemConfigurationType =
  (typeof SYSTEM_CONFIGURATION_TYPES)[number];
