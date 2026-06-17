/**
 * Timestamping Authority (TSA) tools. Requires the TSA license module.
 *
 * Routes:
 *   GET    /api/v1/timestamping/authorities         -> list (204 -> [])
 *   GET    /api/v1/timestamping/authorities/:name   -> single (404 -> TIMESTAMPING-AUTHORITY-003)
 *   POST   /api/v1/timestamping/authorities         -> create (name + policyOid unique)
 *   PUT    /api/v1/timestamping/authorities         -> update (full-replace, name in body)
 *   DELETE /api/v1/timestamping/authorities/:name   -> delete (no inbound refs)
 *
 * A TSA references exactly one signer (must pre-exist) and >=1 NTP client (all
 * must pre-exist). acceptedHashAlgorithms must be non-empty.
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
import { HASH_ALGORITHMS } from './enums.js';

const AUTHORITY_ROUTE = '/api/v1/timestamping/authorities';

const AUTHORITY_SPEC: ConfigSpec = {
  noun: 'tsa_authority',
  nounPlural: 'tsa_authorities',
  label: 'timestamping authority',
  routeCollection: AUTHORITY_ROUTE,
  routeItem: `${AUTHORITY_ROUTE}/{name}`,
  idField: 'name',
  immutableKeys: ['name'],
  // id is server-generated/overridden. No asymmetric fields on a TSA.
  stripFields: ['id'],
  putOnCollection: true,
};

export function registerAuthorityTools(
  server: McpServer,
  client: StreamClient,
): void {
  // --- list + get -----------------------------------------------------------
  registerReadTools(server, client, AUTHORITY_SPEC, {
    listDescription:
      'List timestamping authorities (RFC 3161 TSAs). Each TSA has a name, a ' +
      'policyOid, an enabled flag, exactly one signer, one or more ntpClients, ' +
      'a checkRevocation flag, and acceptedHashAlgorithms. Requires the TSA ' +
      'license module.',
    getDescription:
      'Get a single timestamping authority by name. Requires the TSA module.',
  });

  // --- create ---------------------------------------------------------------
  registerCreateTool(server, client, AUTHORITY_SPEC, {
    description:
      'Create a new timestamping authority. The signer must already exist, all ' +
      'ntpClients must already exist (at least one is required), policyOid must ' +
      'be a valid OID and globally unique across TSAs, and ' +
      'accepted_hash_algorithms must contain at least one value. Requires the ' +
      'TSA module.',
    mandatoryFields: [
      'name',
      'policy_oid',
      'enabled',
      'signer',
      'accepted_hash_algorithms',
      'ntp_clients',
      'check_revocation',
    ],
    inputSchema: z.object({
      name: z
        .string()
        .describe('Unique TSA name (immutable primary key). Ask the user.'),
      policy_oid: z
        .string()
        .describe(
          'Timestamping policy OID (e.g. "1.2.3.4"). Must be a valid OID and ' +
            'globally unique across TSAs.',
        ),
      enabled: z.boolean().describe('Whether the TSA is active.'),
      signer: z
        .string()
        .describe('Name of an existing timestamping signer (must pre-exist).'),
      accepted_hash_algorithms: z
        .array(z.enum(HASH_ALGORITHMS))
        .min(1)
        .describe(
          'Accepted request hash algorithms (at least one). Wire values use the ' +
            'underscore form, e.g. SHA3_256.',
        ),
      ntp_clients: z
        .array(z.string())
        .min(1)
        .describe(
          'Names of existing NTP clients (at least one; all must pre-exist).',
        ),
      check_revocation: z
        .boolean()
        .describe('Whether revocation of the signer certificate is checked.'),
    }),
    buildPayload: (args) => ({
      name: args.name,
      policyOid: args.policy_oid,
      enabled: args.enabled,
      signer: args.signer,
      acceptedHashAlgorithms: args.accepted_hash_algorithms,
      ntpClients: args.ntp_clients,
      checkRevocation: args.check_revocation,
    }),
  });

  // --- update ---------------------------------------------------------------
  registerUpdateTool(server, client, AUTHORITY_SPEC, {
    description:
      'Update a timestamping authority (full-replace, keyed by name; name is ' +
      'required as the lookup key). signer, policyOid, ntpClients and the other ' +
      'fields may all be changed (subject to existence/uniqueness checks). Pass ' +
      'only the fields you want to change; any field you omit keeps its current ' +
      'value (the tool fetches the existing record and merges your changes). All ' +
      'of policy_oid, enabled, signer, accepted_hash_algorithms (>=1), ntp_clients ' +
      '(>=1) and check_revocation remain server-mandatory, so a fully replaced ' +
      'authority must still have all of them. Requires the TSA module.',
    inputSchema: z.object({
      name: z.string().describe('TSA name to update (lookup key).'),
      policy_oid: z
        .string()
        .optional()
        .describe('New timestamping policy OID (valid + globally unique).'),
      enabled: z.boolean().optional().describe('Whether the TSA is active.'),
      signer: z
        .string()
        .optional()
        .describe('Name of an existing timestamping signer.'),
      accepted_hash_algorithms: z
        .array(z.enum(HASH_ALGORITHMS))
        .min(1)
        .optional()
        .describe('Accepted request hash algorithms (at least one).'),
      ntp_clients: z
        .array(z.string())
        .min(1)
        .optional()
        .describe('Names of existing NTP clients (at least one).'),
      check_revocation: z
        .boolean()
        .optional()
        .describe('Whether revocation of the signer certificate is checked.'),
    }),
    buildOverrides: (args) => {
      const overrides: Record<string, unknown> = {};
      if (args.policy_oid !== undefined)
        overrides['policyOid'] = args.policy_oid;
      if (args.enabled !== undefined) overrides['enabled'] = args.enabled;
      if (args.signer !== undefined) overrides['signer'] = args.signer;
      if (args.accepted_hash_algorithms !== undefined) {
        overrides['acceptedHashAlgorithms'] = args.accepted_hash_algorithms;
      }
      if (args.ntp_clients !== undefined) {
        overrides['ntpClients'] = args.ntp_clients;
      }
      if (args.check_revocation !== undefined) {
        overrides['checkRevocation'] = args.check_revocation;
      }
      return overrides;
    },
  });

  // --- delete ---------------------------------------------------------------
  registerDeleteTool(server, client, AUTHORITY_SPEC, {
    description:
      'Delete a timestamping authority by name. TSAs have no inbound references ' +
      'and delete freely. Requires the TSA module.',
  });
}
