/**
 * Audit events domain enums. Wire values are EXACTLY as the server expects them.
 */

// Sortable fields for POST /events/search sortedBy[].element. Validated
// server-side against the event search result fields MINUS details/seal. An
// invalid element yields a 400 EVT-002. (Note: the id field is `id`, not
// `_id`.)
export const EVENT_SORT_FIELDS = [
  'code',
  'id',
  'module',
  'node',
  'removeAt',
  'status',
  'timestamp',
] as const;
export type EventSortField = (typeof EVENT_SORT_FIELDS)[number];

// Event `status` wire values.
export const EVENT_STATUSES = ['warning', 'failure', 'success'] as const;

// Integrity report `status` wire values. May be server-overridden on read.
export const INTEGRITY_REPORT_STATUSES = [
  'running',
  'verified',
  'unexpectedFailure',
  'reportIntegrityFailure',
  'eventIntegrityFailure',
] as const;
