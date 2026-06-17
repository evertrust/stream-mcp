/**
 * HTTP proxy CRUD (api.system.proxy.Routes). Standard name-keyed scaffold:
 * PUT-on-collection-root full-replace, name immutable, 204->[] on list.
 *
 * Audit: docs/audit/system.md sections 4-8.
 *   HttpProxy = { id (server), name (PK), host, port }.
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
} from '../_scaffold.js';

const PROXY_SPEC: ConfigSpec = {
  noun: 'proxy',
  nounPlural: 'proxies',
  label: 'HTTP proxy',
  routeCollection: '/api/v1/system/proxies',
  routeItem: '/api/v1/system/proxies/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  // id is server-managed; the server reuses the previous id on a body-keyed PUT.
  stripFields: ['id'],
  putOnCollection: true,
};

// host validation: RFC952 hostname (>= one dot), or IPv4 / IPv4-range / CIDR,
// or IPv6 / CIDR. Mirrors the server-side patterns documented in the audit so
// the model gets a precise client-side error before the round-trip.
const HOSTNAME_RE =
  /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*(\.[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*)+$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}/;
const IPV6_RE = /^[0-9a-fA-F:]+:[0-9a-fA-F:]*/;

function looksLikeValidHost(host: string): boolean {
  return HOSTNAME_RE.test(host) || IPV4_RE.test(host) || IPV6_RE.test(host);
}

const createSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe(
      'Proxy name (immutable primary key). Ask the user — never infer.',
    ),
  host: z
    .string()
    .min(1)
    .describe(
      'Proxy host: an RFC952 hostname (must contain a dot, e.g. proxy.corp.example.com), an IPv4 address/range/CIDR, or an IPv6 address/CIDR.',
    ),
  port: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .describe('Proxy port, 1..65535 inclusive.'),
});

const updateSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe('Name of the proxy to update (lookup key; immutable).'),
  host: z
    .string()
    .min(1)
    .optional()
    .describe('New host. Omit to keep the current host (full-replace PUT).'),
  port: z
    .number()
    .int()
    .min(1)
    .max(65535)
    .optional()
    .describe('New port (1..65535). Omit to keep the current port.'),
});

function validateHost(host: string | undefined): string | undefined {
  if (host === undefined) return undefined;
  if (!looksLikeValidHost(host)) {
    return JSON.stringify({
      error: 'INVALID_HOST',
      message:
        `host='${host}' is not a valid hostname (needs a dot), IPv4/range/CIDR, or IPv6/CIDR. ` +
        'Stream rejects it with PROXY-002.',
    });
  }
  return undefined;
}

export function registerProxyTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, PROXY_SPEC, {
    listDescription:
      'List configured HTTP proxies (name, host, port). Returns an empty list if none are configured or you lack AUDIT permission.',
    getDescription: 'Get a single HTTP proxy by its exact name.',
  });

  registerCreateTool(server, client, PROXY_SPEC, {
    description:
      'Create an HTTP proxy. Used by keystores, X509 CAs, and triggers for outbound HTTP.',
    mandatoryFields: ['name', 'host', 'port'],
    inputSchema: createSchema,
    preValidate: (args) => validateHost(args.host),
    buildPayload: (args) => ({
      name: args.name,
      host: args.host,
      port: args.port,
    }),
  });

  registerUpdateTool(server, client, PROXY_SPEC, {
    description:
      'Update an HTTP proxy (full-replace by name). Any field you OMIT keeps its current value (the tool re-sends it from the existing record via GET-strip-merge-PUT).',
    inputSchema: updateSchema,
    preValidate: (args) => validateHost(args.host),
    buildOverrides: (args) => ({
      host: args.host,
      port: args.port,
    }),
  });

  registerDeleteTool(server, client, PROXY_SPEC, {
    description: 'Delete an HTTP proxy by name.',
    deleteConstraints:
      'Fails (PROXY-005) if the proxy is referenced by any keystore, X509 CA, or trigger — remove those references first.',
  });
}
