/**
 * Shared helpers for Stream MCP tools: URL encoding, response envelopes,
 * the GET-strip-merge-PUT update cycle, and search payload/response builders.
 */
import { z } from 'zod';

import { StreamError, redactSensitive } from '../client/errors.js';
import type { StreamClient } from '../client/http.js';
import { toUpdatePayload } from '../models/payloads.js';

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
  const sliced = items.slice(0, maxItems);
  return JSON.stringify({
    items: sliced,
    count: sliced.length,
    total_available: total,
    truncated: total > maxItems,
    kind,
  });
}

export function buildMutateResponse(opts: {
  action: string;
  kind: string;
  name: string;
  data?: Record<string, unknown>;
  warnings?: string[];
}): string {
  const response: Record<string, unknown> = {
    status: opts.action,
    kind: opts.kind,
    name: opts.name,
  };
  // Redact any secret material a create/update response might echo back.
  if (opts.data !== undefined) response['data'] = redactSensitive(opts.data);
  if (opts.warnings && opts.warnings.length > 0) {
    response['warnings'] = opts.warnings;
  }
  return JSON.stringify(response);
}

// ---------------------------------------------------------------------------
// GET-strip-merge-PUT cycle (generic; uses a baseline strip set)
// ---------------------------------------------------------------------------

export async function getStripMergePut(
  client: StreamClient,
  getPath: string,
  putPath: string,
  overrides: Record<string, unknown>,
  opts: { stripFields?: Iterable<string>; clearFields?: string[] } = {},
): Promise<Record<string, unknown>> {
  const current = await client.get<Record<string, unknown>>(getPath);
  const payload = toUpdatePayload(current, {
    overrides,
    clearFields: opts.clearFields,
    stripFields: opts.stripFields,
  });
  return client.put<Record<string, unknown>>(putPath, payload);
}

// ---------------------------------------------------------------------------
// Search payload + response builders (Stream search DSL)
// ---------------------------------------------------------------------------

/**
 * Parse a "field:order" string into Stream's sortedBy element.
 * Stream's SortOrder is a case-sensitive enum: Asc | Desc | KeyAsc | KeyDesc
 * (an uppercase "ASC"/"DESC" is rejected with error.expected.validenumvalue).
 * The order suffix is matched case-insensitively and normalized; default Asc.
 */
const SORT_ORDERS: Record<string, string> = {
  asc: 'Asc',
  desc: 'Desc',
  keyasc: 'KeyAsc',
  keydesc: 'KeyDesc',
};

export function buildSortedBy(
  sortedBy?: string,
): Array<{ element: string; order: string }> | undefined {
  if (!sortedBy) return undefined;
  const [rawElement, rawOrder] = sortedBy.split(':', 2);
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
  sortedBy?: string;
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
  const records = Array.isArray(rawRecords)
    ? truncate
      ? (rawRecords as Record<string, unknown>[]).map(truncateRecord)
      : (rawRecords as Record<string, unknown>[])
    : [];

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
