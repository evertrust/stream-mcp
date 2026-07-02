/**
 * Shared helpers for Stream MCP tools: URL encoding, response envelopes,
 * the GET-strip-merge-PUT update cycle, and search payload/response builders.
 */
import { z } from 'zod';

import { StreamError, redactSensitive } from '../client/errors.js';

// ---------------------------------------------------------------------------
// Shared MCP outputSchema shapes
// ---------------------------------------------------------------------------

export const SEARCH_RESPONSE_OUTPUT_SCHEMA = {
  results: z.array(z.record(z.string(), z.unknown())),
  page_index: z.number().int(),
  page_size: z.number().int(),
  total: z.number().nullable(),
  has_more: z.boolean(),
  next_page_index: z.number().int().nullable(),
} as const;

export const MUTATE_RESPONSE_OUTPUT_SCHEMA = {
  status: z.string(),
  kind: z.string(),
  name: z.string(),
  data: z.record(z.string(), z.unknown()).optional(),
  warnings: z.array(z.string()).optional(),
} as const;

// ---------------------------------------------------------------------------
// URL path encoding
// ---------------------------------------------------------------------------

/**
 * Encode a single URL path-segment value. Use for every interpolated
 * identifier to prevent path traversal / request smuggling. Encode only the
 * segment value - never the fixed `/` separators.
 */
export const encodePathSegment = (value: string): string =>
  encodeURIComponent(value);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MAX_PAGE_SIZE = 100;

// Field-level truncation limits (search results only)
const MAX_STRING_LEN = 500;
const MAX_ARRAY_ELEMENTS = 20;
const MAX_NESTED_BYTES = 2048;

// ---------------------------------------------------------------------------
// Safety guard
// ---------------------------------------------------------------------------

export function deleteGuard(
  name: string,
  expected: string,
  label = 'name',
): void {
  if (name !== expected) {
    throw new StreamError(422, {
      errorCode: 'SAFETY-ECHO',
      message:
        `Safety check failed: expected_${label}='${expected}' ` +
        `does not match ${label}='${name}'.`,
      remediation: `Pass expected_${label} equal to ${label} to confirm deletion.`,
    });
  }
}

// ---------------------------------------------------------------------------
// List filtering + response building
// ---------------------------------------------------------------------------

export function applyNameFilter(
  items: Record<string, unknown>[],
  field: string,
  nameContains?: string,
): Record<string, unknown>[] {
  if (!nameContains) return items;
  const needle = nameContains.toLowerCase();
  return items.filter((item) => {
    const v = item[field];
    return typeof v === 'string' && v.toLowerCase().includes(needle);
  });
}

export function buildListResponse(
  items: Record<string, unknown>[],
  maxItems: number,
  kind: string,
): string {
  const total = items.length;
  // Redact secret-bearing fields on read symmetrically with the write path
  // (buildMutateResponse). redactSensitive only touches the known secret-field
  // set; reference names (keystore, credentials, ...) stay visible. Then
  // apply the same field-level truncation as search responses so heavy items
  // (e.g. decoded CA certificates/chains) cannot flood the context.
  const sliced = items
    .slice(0, maxItems)
    .map((item) =>
      truncateRecord(redactSensitive(item) as Record<string, unknown>),
    );
  return JSON.stringify({
    items: sliced,
    count: sliced.length,
    total_available: total,
    truncated: total > maxItems,
    kind,
  });
}

/**
 * JSON-encode a single read result with the same secret redaction the write
 * path applies. Use for get_* tools that return a backed object verbatim, so a
 * secret-bearing field can never reach the model unredacted.
 */
export function redactedJson(value: unknown): string {
  return JSON.stringify(redactSensitive(value));
}

export interface MutateResponseOptions {
  action: string;
  kind: string;
  name: string;
  data?: Record<string, unknown>;
  warnings?: string[];
  /**
   * Top-level fields to INTENTIONALLY return in clear despite matching the
   * sensitive-field set. Use ONLY for one-time secrets the caller must capture
   * (e.g. a server-generated local-identity `password`). Server stderr logs
   * never include tool-result bodies, so these stay out of logs.
   */
  reveal?: readonly string[];
}

/**
 * Build the mutate envelope as an OBJECT (for structuredContent alongside
 * MUTATE_RESPONSE_OUTPUT_SCHEMA). buildMutateResponse is the string form.
 */
export function buildMutateResult(
  opts: MutateResponseOptions,
): Record<string, unknown> {
  const response: Record<string, unknown> = {
    status: opts.action,
    kind: opts.kind,
    name: opts.name,
  };
  // Redact any secret material a create/update response might echo back, then
  // re-surface the explicitly-revealed one-time fields.
  if (opts.data !== undefined) {
    const redacted = redactSensitive(opts.data) as Record<string, unknown>;
    if (opts.reveal) {
      for (const field of opts.reveal) {
        if (opts.data[field] !== undefined) redacted[field] = opts.data[field];
      }
    }
    response['data'] = redacted;
  }
  if (opts.warnings && opts.warnings.length > 0) {
    response['warnings'] = opts.warnings;
  }
  return response;
}

export function buildMutateResponse(opts: MutateResponseOptions): string {
  return JSON.stringify(buildMutateResult(opts));
}

// ---------------------------------------------------------------------------
// Search payload + response builders (Stream search DSL)
// ---------------------------------------------------------------------------

/**
 * Normalize a sort specification into Stream's sortedBy element list.
 * Accepts BOTH input shapes every search tool exposes:
 *   - the compact string form `"field:order"` (single element), and
 *   - the wire-shaped array form `[{ element, order }, ...]`.
 * Stream's SortOrder is a case-sensitive enum: Asc | Desc | KeyAsc | KeyDesc
 * (an uppercase "ASC"/"DESC" is rejected with error.expected.validenumvalue).
 * Orders are matched case-insensitively and normalized; default Asc.
 */
const SORT_ORDERS: Record<string, string> = {
  asc: 'Asc',
  desc: 'Desc',
  keyasc: 'KeyAsc',
  keydesc: 'KeyDesc',
};

export type SortedByInput =
  | string
  | ReadonlyArray<{ element: string; order: string }>;

export function buildSortedBy(
  sortedBy?: SortedByInput,
): Array<{ element: string; order: string }> | undefined {
  if (!sortedBy) return undefined;
  if (Array.isArray(sortedBy)) {
    const elements = sortedBy
      .map(({ element, order }) => ({
        element: element.trim(),
        order: SORT_ORDERS[order.trim().toLowerCase()] ?? 'Asc',
      }))
      .filter((e) => e.element);
    return elements.length > 0 ? elements : undefined;
  }
  const [rawElement, rawOrder] = (sortedBy as string).split(':', 2);
  const element = (rawElement ?? '').trim();
  if (!element) return undefined;
  const order = SORT_ORDERS[(rawOrder ?? 'asc').trim().toLowerCase()] ?? 'Asc';
  return [{ element, order }];
}

/**
 * Build a Stream search request body. An empty query is invalid server-side
 * (STREAMQL-001), so it defaults to `id exists` (matches all). pageIndex is
 * 1-based (Stream-native).
 */
export function buildSearchPayload(opts: {
  query?: string;
  fields?: string[];
  pageIndex?: number;
  pageSize?: number;
  sortedBy?: SortedByInput;
  withCount?: boolean;
}): Record<string, unknown> {
  const pageSize = Math.min(opts.pageSize ?? 20, MAX_PAGE_SIZE);
  const payload: Record<string, unknown> = {
    query: opts.query && opts.query.trim() ? opts.query : 'id exists',
    pageIndex: opts.pageIndex && opts.pageIndex > 0 ? opts.pageIndex : 1,
    pageSize,
  };
  if (opts.fields && opts.fields.length > 0) payload['fields'] = opts.fields;
  const sorted = buildSortedBy(opts.sortedBy);
  if (sorted) payload['sortedBy'] = sorted;
  if (opts.withCount) payload['withCount'] = true;
  return payload;
}

/**
 * Normalize a Stream search envelope into a stable MCP response.
 * Reads results from `results`/`items`, total from `count`, and computes
 * has_more when the server doesn't provide it.
 */
export function buildSearchResponse(
  result: Record<string, unknown>,
  pageIndex: number,
  pageSize: number,
  options: { truncate?: boolean } = {},
): Record<string, unknown> {
  const { truncate = true } = options;
  const cappedPageSize = Math.min(pageSize, MAX_PAGE_SIZE);
  const rawRecords = (result['results'] ?? result['items'] ?? []) as unknown;
  // Redact FIRST (same invariant as every other read path: a secret-bearing
  // field can never reach the model unredacted), then truncate.
  const redacted = Array.isArray(rawRecords)
    ? (rawRecords as Record<string, unknown>[]).map(
        (r) => redactSensitive(r) as Record<string, unknown>,
      )
    : [];
  const records = truncate ? redacted.map(truncateRecord) : redacted;

  const total =
    typeof result['count'] === 'number' ? (result['count'] as number) : null;

  let hasMore: boolean;
  if (typeof result['hasMore'] === 'boolean') {
    hasMore = result['hasMore'] as boolean;
  } else if (total !== null) {
    hasMore = pageIndex * cappedPageSize < total;
  } else {
    hasMore = records.length >= cappedPageSize;
  }

  return {
    results: records,
    page_index: pageIndex,
    page_size: cappedPageSize,
    total,
    has_more: hasMore,
    next_page_index: hasMore ? pageIndex + 1 : null,
  };
}

// ---------------------------------------------------------------------------
// Field-level truncation (search results only)
// ---------------------------------------------------------------------------

function truncateValue(value: unknown): unknown {
  if (typeof value === 'string' && value.length > MAX_STRING_LEN) {
    return `${value.slice(0, MAX_STRING_LEN)}... <truncated: fetch the single object for the full value>`;
  }
  if (Array.isArray(value)) {
    const total = value.length;
    const truncated = value
      .slice(0, MAX_ARRAY_ELEMENTS)
      .map((item) => truncateValue(item));
    if (total > MAX_ARRAY_ELEMENTS) {
      truncated.push(
        `<truncated: ${total} total, showing first ${MAX_ARRAY_ELEMENTS}>`,
      );
    }
    return truncated;
  }
  if (typeof value === 'object' && value !== null) {
    const serialized = JSON.stringify(value);
    if (new TextEncoder().encode(serialized).length > MAX_NESTED_BYTES) {
      return '<oversized: fetch the single object>';
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) result[k] = truncateValue(v);
    return result;
  }
  return value;
}

export function truncateRecord(
  record: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    result[key] = truncateValue(value);
  }
  return result;
}
