/**
 * CRL series tools (Stream 2.2+, require the stream-offline-ca license):
 *   preview_crl_series, generate_crl_series, list_crl_series,
 *   download_crl_series, delete_crl_series.
 *
 * A CRL series is a set of future-dated CRLs signed in advance for a managed
 * CA (typically an offline root). Flow: preview -> generate (async job) ->
 * poll list -> download (zip of DER CRLs) -> delete.
 * Public reference: https://docs.evertrust.fr/stream/2.2/api-ref/x509_ca_crls_preview.html
 */
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { type ConfigSpec, registerDeleteTool } from '../_scaffold.js';
import {
  buildListResponse,
  buildMutateResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';

import { DURATION_RE } from './enums.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const JOBS_ROUTE = '/api/v1/x509/crlseries';
const LICENSE_NOTE = 'Stream 2.2+, requires the stream-offline-ca license.';
const MAX_SERIES = 100;

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

const SPEC: ConfigSpec = {
  noun: 'crl_series',
  nounPlural: 'crl_series',
  label: 'CRL series job',
  routeCollection: JOBS_ROUTE,
  routeItem: `${JOBS_ROUTE}/{id}`,
  idField: 'id',
  immutableKeys: ['id'],
  stripFields: [],
  putOnCollection: false,
  knowledgeRef: 'stream://knowledge/ca-management',
};

const caCrlsPath = (name: string, suffix = ''): string =>
  `/api/v1/x509/cas/${encodePathSegment(name)}/crls${suffix}`;

const duration = z
  .string()
  .regex(DURATION_RE, 'Must be a duration like "365 days".');

const seriesItem = z.object({
  thisUpdate: z.string().describe('ISO-8601 instant.'),
  nextUpdate: z.string().describe('ISO-8601 instant.'),
});

export function registerCrlSeriesTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'preview_crl_series',
    {
      description:
        'Compute the dates of a series of future-dated CRLs for a managed CA, ' +
        'without signing or storing anything. Pass the returned series ' +
        `unchanged to generate_crl_series. ${LICENSE_NOTE}\n` +
        'The first CRL runs from start for validity. Each next CRL starts ' +
        "overlap before the previous CRL's nextUpdate and ends validity after " +
        'it. The series stops at the first CRL whose nextUpdate reaches end or ' +
        'the CA expiration (max 100 CRLs). Invalid parameters return CA-020.',
      annotations: READ_ONLY,
      inputSchema: z.object({
        name: z.string().describe('Name of the managed CA.'),
        start: z
          .string()
          .describe(
            'thisUpdate of the first CRL (ISO-8601). Not before 00:00 UTC ' +
              'today or the CA notBefore. Use 00:00:00Z to align on midnight UTC.',
          ),
        end: z
          .string()
          .describe(
            'ISO-8601 instant where the series stops. Not after the CA notAfter.',
          ),
        overlap: duration.describe(
          "How long each CRL starts before the previous CRL's nextUpdate, " +
            'e.g. "61 days". Shorter than validity.',
        ),
        validity: duration.describe(
          'Length of the first CRL and step between nextUpdates, e.g. "365 days".',
        ),
      }),
    },
    async ({ name, start, end, overlap, validity }) => {
      const series = await client.post<unknown[]>(
        caCrlsPath(name, '/preview'),
        {
          start,
          end,
          overlap,
          validity,
        },
      );
      const items = series ?? [];
      return text(
        JSON.stringify({ ca: name, count: items.length, series: items }),
      );
    },
  );

  registerTool(
    server,
    'generate_crl_series',
    {
      description:
        'Start an async job that signs a series of future-dated CRLs with the ' +
        'CA key. Send the series from preview_crl_series. Returns the job ' +
        `(status pending); poll list_crl_series until it is succeeded. ${LICENSE_NOTE}\n` +
        'One job per CA at a time (CA-021). For a single CRL now, use generate_crl.',
      inputSchema: z.object({
        name: z.string().describe('Name of the managed CA.'),
        series: z
          .array(seriesItem)
          .min(1)
          .max(MAX_SERIES)
          .describe('The series returned by preview_crl_series, in order.'),
      }),
    },
    async ({ name, series }) => {
      const job = await client.post<Record<string, unknown>>(
        caCrlsPath(name),
        series,
      );
      return text(
        buildMutateResponse({
          action: 'queued',
          kind: SPEC.noun,
          name,
          data: job ?? undefined,
        }),
      );
    },
  );

  registerTool(
    server,
    'list_crl_series',
    {
      description:
        'List the CRL series jobs of every CA, newest first, with status ' +
        `(pending, running, succeeded, failed) and progress. ${LICENSE_NOTE}`,
      inputSchema: z.object({
        max_items: z.number().int().positive().max(100).default(50),
      }),
    },
    async ({ max_items }) => {
      const jobs = await client.getList<Record<string, unknown>>(JOBS_ROUTE);
      return text(buildListResponse(jobs, max_items, SPEC.noun));
    },
  );

  registerTool(
    server,
    'download_crl_series',
    {
      description:
        'Download the CRLs of a succeeded CRL series job as a base64 zip of ' +
        `DER CRLs, in series order (10 MiB max). ${LICENSE_NOTE}\n` +
        'A job that has not succeeded returns CA-023.',
      annotations: READ_ONLY,
      inputSchema: z.object({
        id: z.string().describe('CRL series job id (from list_crl_series).'),
      }),
    },
    async ({ id }) => {
      const buf = await client.getBytes(
        `${JOBS_ROUTE}/${encodePathSegment(id)}`,
        client.exportTimeout,
      );
      return text(
        JSON.stringify({
          id,
          contentType: 'application/zip',
          base64: Buffer.from(buf).toString('base64'),
        }),
      );
    },
  );

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete a CRL series job and its CRLs. A pending or running job cannot ' +
      `be deleted (CA-023). ${LICENSE_NOTE}`,
  });
}
