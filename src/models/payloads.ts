/**
 * Shared payload helpers for the GET-strip-merge-PUT update cycle.
 *
 * Stream's update endpoints are full-replace PUTs keyed by the body's id field
 * (`name`/`identifier`/`oid`/`type`). To update one field we GET the current
 * object, strip server-managed fields, merge the caller's overrides, and PUT
 * the result. `_scaffold.ts` carries an explicit per-object strip set; this
 * module provides the generic helper + a baseline strip set.
 */

/** Fields that are server-managed on virtually every Stream object. */
export const BASELINE_STRIP: ReadonlySet<string> = new Set(['_id', 'id']);

/**
 * Build a full-replace PUT body from a fetched object:
 * strip server-managed fields, null any `clearFields`, then apply `overrides`
 * (undefined/null overrides are ignored so callers can pass sparse objects).
 */
export function toUpdatePayload(
  response: Record<string, unknown>,
  opts: {
    overrides?: Record<string, unknown>;
    clearFields?: string[];
    stripFields?: Iterable<string>;
  } = {},
): Record<string, unknown> {
  const strip = new Set<string>(opts.stripFields ?? BASELINE_STRIP);

  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(response)) {
    if (!strip.has(k)) payload[k] = v;
  }

  for (const field of opts.clearFields ?? []) {
    payload[field] = null;
  }

  for (const [key, value] of Object.entries(opts.overrides ?? {})) {
    if (value !== undefined && value !== null) {
      payload[key] = value;
    }
  }

  return payload;
}
