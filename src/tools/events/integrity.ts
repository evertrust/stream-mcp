/**
 * Event integrity tools: trigger a chain-integrity verification and list the
 * produced integrity reports.
 * Endpoints:
 *   - GET /events/integrity/run?startFrom=<objectId>  -> 204 (fire-and-forget)
 *   - GET /events/integrity                           -> EventIntegrityReport[]
 *
 * Both require chainsign=true + seal.secret on the server; otherwise the
 * server returns 400 EVT-INTEGRITY-002. The list endpoint returns 204 (not 403)
 * on permission failure, which getList maps to an empty array.
 *
 * Audit contract: docs/audit/events.md.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import { buildListResponse } from '../helpers.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerTool } from '../register.js';

const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const MAX_REPORTS = 100;

// ---------------------------------------------------------------------------
// run_event_integrity_check
// ---------------------------------------------------------------------------

const RUN_INPUT = z.object({
  start_from: z
    .string()
    .optional()
    .describe(
      'Optional event id (24-hex ObjectId) to start verification from ' +
        '($gte). Omit to verify from the beginning of the event log.',
    ),
});

function registerRun(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'run_event_integrity_check',
    {
      description:
        'Trigger an asynchronous chain-integrity verification of the sealed ' +
        'audit-event log. Fire-and-forget: returns immediately (no report ' +
        'inline). Poll list_event_integrity_reports afterwards for the produced ' +
        'EventIntegrityReport. Requires chainsign + seal.secret configured.',
      inputSchema: RUN_INPUT,
    },
    async (args) => {
      let params: URLSearchParams | undefined;
      if (args.start_from !== undefined) {
        if (!OBJECT_ID_RE.test(args.start_from)) {
          throw new StreamError(400, {
            errorCode: 'CLIENT-VALIDATION',
            message: `Invalid start_from '${args.start_from}': expected a 24-hex ObjectId.`,
            remediation:
              'Use search_events to find an event id, then pass it as start_from.',
          });
        }
        params = new URLSearchParams({ startFrom: args.start_from });
      }
      await client.get('/api/v1/events/integrity/run', params);
      return text(
        JSON.stringify({
          status: 'triggered',
          message:
            'Integrity verification started in the background. Poll ' +
            'list_event_integrity_reports for the produced report.',
          ...(args.start_from !== undefined
            ? { startFrom: args.start_from }
            : {}),
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// list_event_integrity_reports
// ---------------------------------------------------------------------------

function registerList(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'list_event_integrity_reports',
    {
      description:
        'List all event integrity reports. Each report re-verifies its own ' +
        'seal on the fly, so the returned status/error may differ from the ' +
        'stored values. Statuses: running, verified, unexpectedFailure, ' +
        'reportIntegrityFailure, eventIntegrityFailure. Requires chainsign + ' +
        'seal.secret; empty list if not configured or no permission.',
      inputSchema: z.object({}),
    },
    async () => {
      const reports = await client.getList<Record<string, unknown>>(
        '/api/v1/events/integrity',
      );
      return text(
        buildListResponse(reports, MAX_REPORTS, 'event_integrity_report'),
      );
    },
  );
}

export function registerEventIntegrityTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerRun(server, client);
  registerList(server, client);
}
