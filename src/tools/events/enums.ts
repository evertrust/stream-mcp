/**
 * Audit events domain enums (live-verified against the Stream 2.1 source +
 * captured QA dictionary). Wire values are EXACTLY as the server expects them.
 *
 * Audit contract: docs/audit/events.md.
 */

// Sortable fields for POST /events/search sortedBy[].element. Validated server
// -side against EventSearchResult MINUS details/seal. An invalid element yields
// a 400 EVT-002. (Note: the id field is `id`, not `_id`, in the validator.)
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

// EventStatus (wire = entryName).
export const EVENT_STATUSES = ['warning', 'failure', 'success'] as const;

// IntegrityReportStatus (wire = entryName). May be server-overridden on read.
export const INTEGRITY_REPORT_STATUSES = [
  'running',
  'verified',
  'unexpectedFailure',
  'reportIntegrityFailure',
  'eventIntegrityFailure',
] as const;
