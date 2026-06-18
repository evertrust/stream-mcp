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
  registerDeleteTool,
  registerDescribeSchemaTool,
  registerReadTools,
} from '../_scaffold.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import { StreamError } from '../../client/errors.js';

import { CA_TYPES } from './enums.js';
import { CA_JSON_SCHEMA, caConfigSchema } from './schema.js';
import { validateCaConfig, validateCaUpdateConfig } from './validate.js';

const ROUTE_COLLECTION = '/api/v1/cas';
const KNOWLEDGE_REF = 'docs/audit/x509-ca.md';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

/**
 * Server-managed fields that are OPTIONAL in the case-class JSON reads, so they
 * can be dropped from the update PUT body entirely. The server resets them
 * (updateFrom resets revoked/revocationDate/revocationReason and takes id from
 * the previous record) — never author them.
 *
 * NOTE: `privateKey` (managed) and `certificate` (managed-issued + external) are
 * deliberately NOT dropped: they are REQUIRED for the body to deserialize
 * (`validate[X509CertificateAuthority]` runs BEFORE `updateFrom`; managed
 * `privateKey` has no default, external `certificate` is `require`d by the
 * constructor). They are carried over from the GET in update_ca (certificate is
 * converted from the rich-on-read object to its PEM string, which is the only
 * shape the reads accept). `dn` is also carried over from the GET so a PENDING
 * managed CA (no cert) keeps its mandatory dn; an issued CA's GET has dn=null.
 */
/**
 * Server-managed / revocation fields that Stream's `updateFrom` resets on any
 * full-replace PUT /api/v1/cas. SINGLE SOURCE OF TRUTH for the CA update
 * contract: both update_ca (here) and assign_ocsp_signer_to_ca
 * (revocation/signers.ts) strip exactly these. assign_ additionally strips
 * `certificate`/`altPrivateKey` (it does not round-trip them), whereas update_ca
 * keeps and PEM-converts the certificate so the body still deserializes.
 */
export const CA_SERVER_MANAGED_STRIP_FIELDS = [
  'id',
  'revoked',
  'revocationDate',
  'revocationReason',
] as const;

const STRIP_FIELDS = CA_SERVER_MANAGED_STRIP_FIELDS;

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
        'MANDATORY (both types): type, name, trustedForClientAuthentication, ' +
        'trustedForServerAuthentication.\n' +
        'MANDATORY (type=managed): enroll, enforceKeyUnicity, privateKey ' +
        '(keystore + name), and dn when no certificate is supplied (dn must be ' +
        'OMITTED when a certificate is supplied).\n' +
        'MANDATORY (type=external): certificate (PEM), ' +
        'outdatedRevocationStatusPolicy (revoked | unknown | lastavailablestatus).\n' +
        'Ask the user for every mandatory value; do NOT infer, default, or invent ' +
        'any of them — especially name (an immutable primary key) and the ' +
        'trustedFor* booleans (no server default).\n' +
        'Never author revoked/revocationDate/revocationReason/id (server-managed).\n' +
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
        'MANDATORY: name (the immutable lookup key) and type. Ask the user for the ' +
        'name; never invent it — a wrong name is a different CA (404 CA-003). ' +
        'name and type are immutable and cannot be changed.\n' +
        'This is a full-replace done as GET -> merge your config -> PUT: any ' +
        'field you OMIT keeps its current value (the tool re-sends it from the ' +
        'existing record). ' +
        'certificate/privateKey/altPrivateKey/dn and revoked* are carried over / ' +
        'reset from the previous record automatically. Never author ' +
        'revoked/revocationDate/revocationReason/id (server-managed).\n' +
        `Ref: ${KNOWLEDGE_REF}.`,
      inputSchema: z.object({ config: caConfigSchema }),
    },
    async ({ config }) => {
      validateCaUpdateConfig(config);
      const getPath = `${ROUTE_COLLECTION}/${encodePathSegment(config.name)}`;
      const current = await client.get<Record<string, unknown>>(getPath);
      if (
        current === null ||
        typeof current !== 'object' ||
        Array.isArray(current)
      ) {
        throw new StreamError(502, {
          errorCode: 'CONFIG-BAD-GET',
          message: `Expected a single object from ${getPath} before update.`,
        });
      }
      // Build the PUT body from the current record:
      //  - drop server-reset OPTIONAL fields (id/revoked/revocationDate/
      //    revocationReason) — they have no JSON default and are reset by
      //    updateFrom anyway;
      //  - convert the rich-on-read `certificate` object to its PEM string (the
      //    only shape the reads accept); keep `privateKey`/`altPrivateKey`/`dn`
      //    so the body deserializes (managed privateKey is required; external
      //    certificate is required; a pending CA's dn is mandatory).
      const strip = new Set<string>(STRIP_FIELDS);
      const payload: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(current)) {
        if (strip.has(k)) continue;
        if (
          k === 'certificate' &&
          v !== null &&
          typeof v === 'object' &&
          !Array.isArray(v)
        ) {
          const pem = (v as Record<string, unknown>)['pem'];
          if (typeof pem === 'string') {
            payload['certificate'] = pem;
            continue;
          }
        }
        payload[k] = v;
      }
      // Apply user overrides for mutable fields (certificate/privateKey/dn are
      // server-restored on issued CAs but harmless to override; the server
      // honors only usePSS/hashAlgorithm from privateKey).
      for (const [k, v] of Object.entries(config)) {
        if (v !== undefined && !strip.has(k)) payload[k] = v;
      }
      const result = await client.put<Record<string, unknown>>(
        ROUTE_COLLECTION,
        payload,
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
