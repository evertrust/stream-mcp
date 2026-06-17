/**
 * NTP Client tools (TSA domain). Requires the TSA license module.
 *
 * Routes:
 *   GET    /api/v1/timestamping/ntps         -> list (204 -> [])
 *   GET    /api/v1/timestamping/ntps/:name   -> single (404 -> NTP-003)
 *   POST   /api/v1/timestamping/ntps         -> create (name unique)
 *   PUT    /api/v1/timestamping/ntps         -> update (full-replace, name in body)
 *   DELETE /api/v1/timestamping/ntps/:name   -> delete (403 NTP-005 if a TSA references it)
 *
 * An NTP client is a standalone NTP server config (host/port/timeout + optional
 * sanity bounds). It is referenced by TSAs via ntpClients.
 *
 * Grounded in docs/audit/tsa.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
} from '../_scaffold.js';

const NTP_ROUTE = '/api/v1/timestamping/ntps';

const NTP_SPEC: ConfigSpec = {
  noun: 'ntp_client',
  nounPlural: 'ntp_clients',
  label: 'NTP client',
  routeCollection: NTP_ROUTE,
  routeItem: `${NTP_ROUTE}/{name}`,
  idField: 'name',
  immutableKeys: ['name'],
  // id is server-generated/overridden. No asymmetric fields on an NTP client.
  stripFields: ['id'],
  putOnCollection: true,
};

const portSchema = z
  .number()
  .int()
  .min(1)
  .max(65535)
  .describe('NTP server port (1..65535). Defaults to 123 if omitted.');

const timeoutSchema = z
  .string()
  .describe(
    'Query timeout as a FiniteDuration string, e.g. "10 seconds", "5 s", ' +
      '"500 ms". Client default is 5 seconds when omitted.',
  );

const maxStratumSchema = z
  .number()
  .int()
  .min(0)
  .max(15)
  .describe('Max acceptable stratum (0..15).');

const maxOffsetSchema = z
  .string()
  .describe(
    'Max acceptable clock offset as a FiniteDuration string (> 0 ms), e.g. ' +
      '"100 ms".',
  );

const maxRttSchema = z
  .number()
  .int()
  .positive()
  .describe('Max acceptable round-trip time in milliseconds (> 0).');

export function registerNtpTools(
  server: McpServer,
  client: StreamClient,
): void {
  // --- list + get -----------------------------------------------------------
  registerReadTools(server, client, NTP_SPEC, {
    listDescription:
      'List NTP clients (standalone NTP server configs referenced by TSAs). ' +
      'Each has a name, host, and optional port/timeout/sanity bounds. ' +
      'Requires the TSA license module.',
    getDescription: 'Get a single NTP client by name. Requires the TSA module.',
  });

  // --- create ---------------------------------------------------------------
  registerCreateTool(server, client, NTP_SPEC, {
    description:
      'Create a new NTP client. host must be a valid RFC-952 hostname (at least ' +
      'one dot) or an IPv4/IPv6 address (incl. CIDR/range forms). port/timeout ' +
      'and the sanity bounds are optional. Requires the TSA module.',
    mandatoryFields: ['name', 'host'],
    inputSchema: z.object({
      name: z
        .string()
        .describe(
          'Unique NTP client name (immutable primary key). Ask the user.',
        ),
      host: z
        .string()
        .describe(
          'NTP server host: RFC-952 hostname (e.g. "time1.google.com") or ' +
            'IPv4/IPv6 address (incl. CIDR/range forms).',
        ),
      description: z.string().optional().describe('Free-text description.'),
      port: portSchema.optional(),
      timeout: timeoutSchema.optional(),
      max_stratum: maxStratumSchema.optional(),
      max_offset: maxOffsetSchema.optional(),
      max_rtt: maxRttSchema.optional(),
    }),
    buildPayload: (args) => {
      const body: Record<string, unknown> = {
        name: args.name,
        host: args.host,
      };
      if (args.description !== undefined)
        body['description'] = args.description;
      if (args.port !== undefined) body['port'] = args.port;
      if (args.timeout !== undefined) body['timeout'] = args.timeout;
      if (args.max_stratum !== undefined) body['maxStratum'] = args.max_stratum;
      if (args.max_offset !== undefined) body['maxOffset'] = args.max_offset;
      if (args.max_rtt !== undefined) body['maxRTT'] = args.max_rtt;
      return body;
    },
  });

  // --- update ---------------------------------------------------------------
  registerUpdateTool(server, client, NTP_SPEC, {
    description:
      'Update an NTP client (full-replace, keyed by name; name is required as ' +
      'the lookup key). host stays mandatory on the stored record. Pass only the ' +
      'fields you want to change; any field you omit keeps its current value (the ' +
      'tool fetches the existing record and merges your changes). To null an ' +
      'optional field (e.g. maxStratum) use clear_fields. Requires the TSA module.',
    inputSchema: z.object({
      name: z.string().describe('NTP client name to update (lookup key).'),
      host: z
        .string()
        .optional()
        .describe('NTP server host (RFC-952 hostname or IPv4/IPv6 address).'),
      description: z.string().optional().describe('Free-text description.'),
      port: portSchema.optional(),
      timeout: timeoutSchema.optional(),
      max_stratum: maxStratumSchema.optional(),
      max_offset: maxOffsetSchema.optional(),
      max_rtt: maxRttSchema.optional(),
      clear_fields: z
        .array(z.string())
        .optional()
        .describe(
          'Field names to explicitly null out (e.g. ["maxStratum"]). Cannot ' +
            'target immutable or server-managed fields.',
        ),
    }),
    buildOverrides: (args) => {
      const overrides: Record<string, unknown> = {};
      if (args.host !== undefined) overrides['host'] = args.host;
      if (args.description !== undefined) {
        overrides['description'] = args.description;
      }
      if (args.port !== undefined) overrides['port'] = args.port;
      if (args.timeout !== undefined) overrides['timeout'] = args.timeout;
      if (args.max_stratum !== undefined) {
        overrides['maxStratum'] = args.max_stratum;
      }
      if (args.max_offset !== undefined)
        overrides['maxOffset'] = args.max_offset;
      if (args.max_rtt !== undefined) overrides['maxRTT'] = args.max_rtt;
      return overrides;
    },
  });

  // --- delete ---------------------------------------------------------------
  registerDeleteTool(server, client, NTP_SPEC, {
    description: 'Delete an NTP client by name. Requires the TSA module.',
    deleteConstraints:
      'Fails (403 NTP-005) if any TSA still references this NTP client via its ' +
      'ntpClients list; remove the reference on the TSA(s) first.',
  });
}
