/**
 * Core CRUD + schema tools for X509 Certificate Authorities:
 *   list_cas, get_ca, describe_ca_schema, create_ca, update_ca, delete_ca.
 *
 * create_ca / update_ca are polymorphic (managed vs external). The full body is
 * a single validated `config` (typed superset) so the model passes the whole
 * shape; validateCaConfig enforces the disjoint field sets and the dn/cert and
 * crlUrls quirks. update_ca uses GET-strip-merge-PUT with an explicit strip set
 * (certificate/privateKey/altPrivateKey/dn/revoked* are server-restored).
 */
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
  registerDeleteTool,
  registerDescribeSchemaTool,
  registerReadTools,
} from '../_scaffold.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';

import { CA_TYPES } from './enums.js';
import { CA_JSON_SCHEMA, caConfigSchema } from './schema.js';
import { validateCaConfig, validateCaUpdateConfig } from './validate.js';

const ROUTE_COLLECTION = '/api/v1/cas';
const KNOWLEDGE_REF = 'docs/audit/x509-ca.md';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

/**
 * Strip set for update PUT. Beyond name (immutable) we MUST strip every field
 * the server restores/recomputes from the previous record so the body never
 * sends a rich-on-read value where the server expects a PEM/string:
 *   - certificate (PEM in / rich out), privateKey, altPrivateKey, dn
 *   - revoked / revocationDate / revocationReason (server-computed, reset)
 *   - id (server-assigned)
 */
const STRIP_FIELDS = [
  'id',
  'certificate',
  'privateKey',
  'altPrivateKey',
  'dn',
  'revoked',
  'revocationDate',
  'revocationReason',
] as const;

const SPEC: ConfigSpec = {
  noun: 'ca',
  nounPlural: 'cas',
  label: 'Certificate Authority',
  routeCollection: ROUTE_COLLECTION,
  routeItem: '/api/v1/cas/{name}',
  idField: 'name',
  immutableKeys: ['name', 'type'],
  stripFields: STRIP_FIELDS,
  putOnCollection: true,
  knowledgeRef: KNOWLEDGE_REF,
};

export function registerCaCrudTools(
  server: McpServer,
  client: StreamClient,
): void {
  // list_cas + get_ca via scaffold (204 -> []; getList handles empty/forbidden).
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List all X509 Certificate Authorities (managed + external). Optionally ' +
      'filter by type. Empty/forbidden collections return []. Certificates are ' +
      'rich decoded objects on read.',
    getDescription:
      'Get one Certificate Authority by name. Returns the full object; the ' +
      '`certificate` field is a rich decoded object (PEM under .pem).',
  });

  // describe_ca_schema: the model should call this before create/update.
  registerDescribeSchemaTool(server, {
    noun: 'ca',
    label: 'an X509 Certificate Authority (create/update body)',
    discriminatorField: 'type',
    subtypes: CA_TYPES,
    mandatoryFields: [
      'type',
      'name',
      'trustedForClientAuthentication',
      'trustedForServerAuthentication',
      'managed: enroll, enforceKeyUnicity, privateKey, dn(when no certificate)',
      'external: certificate, outdatedRevocationStatusPolicy',
    ],
    jsonSchema: CA_JSON_SCHEMA,
    schemaVersion: '1',
    knowledgeRef: KNOWLEDGE_REF,
  });

  // create_ca (POST /api/v1/cas) -- polymorphic.
  registerTool(
    server,
    'create_ca',
    {
      description:
        'Register a new Certificate Authority. Supports: (a) managed-from-scratch ' +
        '(type=managed, dn + privateKey, no certificate) then drive issuance via ' +
        'generate_ca_csr + issue_ca; (b) external import (type=external, certificate ' +
        'PEM mandatory, crlUrls must be http://); (c) managed import (certificate PEM ' +
        '+ matching privateKey, no dn). Call describe_ca_schema first.\n' +
        'Safety tier: mutating-safe\n' +
        'IMPORTANT: name is an immutable primary key — ask the user for it; never ' +
        'invent it. Never author revoked/revocationDate/revocationReason/id.\n' +
        `Ref: ${KNOWLEDGE_REF}.`,
      inputSchema: z.object({ config: caConfigSchema }),
    },
    async ({ config }) => {
      validateCaConfig(config);
      const result = await client.post<Record<string, unknown>>(
        ROUTE_COLLECTION,
        config,
      );
      return text(
        buildMutateResponse({
          action: 'created',
          kind: 'ca',
          name: config.name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  // update_ca (PUT /api/v1/cas — full replace, body-keyed by name).
  registerTool(
    server,
    'update_ca',
    {
      description:
        'Update an existing Certificate Authority (PUT full-replace, keyed by the ' +
        'config `name`). GET -> strip server-managed fields -> merge your config -> ' +
        'PUT. The previous record restores certificate/privateKey/altPrivateKey/dn ' +
        'and resets revoked* — to change cert/key use issue_ca / enhance_ca / ' +
        'migrate_ca, NOT update_ca. Call describe_ca_schema first.\n' +
        'Safety tier: mutating-safe\n' +
        `name and type are immutable. Ref: ${KNOWLEDGE_REF}.`,
      inputSchema: z.object({ config: caConfigSchema }),
    },
    async ({ config }) => {
      validateCaUpdateConfig(config);
      const getPath = `${ROUTE_COLLECTION}/${encodePathSegment(config.name)}`;
      // overrides = the whole config minus strip fields (they are restored).
      const overrides: Record<string, unknown> = {};
      const strip = new Set<string>(STRIP_FIELDS);
      for (const [k, v] of Object.entries(config)) {
        if (v !== undefined && !strip.has(k)) overrides[k] = v;
      }
      const result = await getStripMergePutExplicit(
        client,
        getPath,
        ROUTE_COLLECTION,
        STRIP_FIELDS,
        overrides,
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'ca',
          name: config.name,
          data: result,
        }),
      );
    },
  );

  // delete_ca (DELETE /api/v1/cas/:name) via scaffold (echo guard).
  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete a Certificate Authority by name. Managed CAs referenced by issued ' +
      'certificates are rejected (CA-005) — remove references first.',
    deleteConstraints:
      'Also deletes stored CRL/CRL-info and CA-scoped permissions; for a root, ' +
      'its own certificate row.',
  });
}
