/**
 * Enums for the utilities domain.
 * On-the-wire values are exactly what Stream parses; keep casing intact.
 */

/**
 * Trust chain order — `?order=` query param for the trust-chain build endpoint.
 */
export const TRUST_CHAIN_ORDERS = ['ltr', 'rtl', 'irtl', 'iltr'] as const;
export type ChainOrder = (typeof TRUST_CHAIN_ORDERS)[number];
