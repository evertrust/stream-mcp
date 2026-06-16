/**
 * Enums for the utilities domain (live-verified against docs/audit/utilities.md).
 * On-the-wire values are exactly what Stream parses; keep casing intact.
 */

/**
 * TrustChainOrder — `?order=` query param for the trust-chain build endpoint
 * (controllers.api.rfc5280.TrustChainOrder, PlayEnum entryName).
 */
export const TRUST_CHAIN_ORDERS = ['ltr', 'rtl', 'irtl', 'iltr'] as const;
export type TrustChainOrder = (typeof TRUST_CHAIN_ORDERS)[number];
