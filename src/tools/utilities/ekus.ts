/**
 * Extended Key Usage (EKU) CRUD. EKUs are keyed by `oid` (immutable); only
 * `name` is mutable; `custom` is server-controlled (true for user-registered
 * EKUs, false for library defaults). Standard/default EKUs cannot be updated or
 * deleted (EKU-005). Both `name` and `oid` must be globally unique.
 *
 * Read (list/get) + delete reuse the scaffold (idField `oid`, with the
 * expected_oid echo guard on delete). Create and update are custom because the
 * wire contract is a flat JSON body (`{name, oid}` on create — server forces
 * custom=true; `{oid, name}` on update — PUT-on-collection-root, oid is the
 * lookup key, only name changes) rather than a GET-strip-merge-PUT cycle.
 *
 * Audit: docs/audit/utilities.md (EKU endpoints).
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  registerDeleteTool,
  registerReadTools,
} from '../_scaffold.js';
import { buildMutateResponse } from '../helpers.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const EKU_SPEC: ConfigSpec = {
  noun: 'eku',
  nounPlural: 'ekus',
  label: 'extended key usage',
  routeCollection: '/api/v1/extension/ekus',
  routeItem: '/api/v1/extension/ekus/{oid}',
  idField: 'oid',
  // oid is the immutable key; custom is server-controlled.
  immutableKeys: ['oid', 'custom'],
  stripFields: ['custom'],
  putOnCollection: true,
};

// A well-formed dotted OID (BouncyCastle ASN1ObjectIdentifier accepts any
// well-formed OID, e.g. "1.3.4"). Client-side pre-check so the model gets a
// precise error before the round-trip (server returns EKU-002 otherwise).
const OID_RE = /^[0-9]+(\.[0-9]+)+$/;

export function registerEkuTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, EKU_SPEC, {
    listDescription:
      'List all Extended Key Usages (library defaults + custom), merged and ' +
      'de-duplicated by OID and sorted by name. Each element is { name, oid, custom }. ' +
      'Always returns the built-in defaults (never empty).',
    getDescription:
      'Get one Extended Key Usage by its OID. Returns { name, oid, custom }.',
  });

  registerTool(
    server,
    'create_eku',
    {
      description:
        'Register a new custom Extended Key Usage. The server forces custom=true. ' +
        'Both name and oid must be globally unique across defaults and custom EKUs ' +
        '(else EKU-004). The oid is the immutable key.\nSafety tier: mutating-safe\n' +
        'MANDATORY fields: name, oid. Ask the user for both — never infer them.',
      inputSchema: z.object({
        name: z
          .string()
          .min(1)
          .describe(
            'Display name (globally unique across all EKUs). Ask the user — never infer.',
          ),
        oid: z
          .string()
          .min(1)
          .describe(
            'Dotted OID, e.g. "1.3.6.1.4.1.311.20.2.2" (immutable primary key, ' +
              'globally unique). Ask the user — never infer.',
          ),
      }),
    },
    async ({ name, oid }) => {
      if (!OID_RE.test(oid)) {
        return text(
          JSON.stringify({
            error: 'INVALID_OID',
            message: `oid='${oid}' is not a well-formed dotted OID (e.g. 1.3.6.1.4.1.311.20.2.2). Stream rejects it with EKU-002.`,
          }),
        );
      }
      // `custom` is server-forced to true, but Stream's play-json Reads makes the
      // field MANDATORY on the wire (no default in the JSON parser) — omitting it
      // returns 400 EKU-002 "/custom: error.path.missing". Send custom:true.
      const result = await client.post<Record<string, unknown>>(
        '/api/v1/extension/ekus',
        { name, oid, custom: true },
      );
      return text(
        buildMutateResponse({
          action: 'created',
          kind: 'eku',
          name: oid,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  registerTool(
    server,
    'update_eku',
    {
      description:
        'Update an existing CUSTOM Extended Key Usage. The oid selects the target ' +
        '(immutable lookup key) and is sent in the body — there is no path param ' +
        '(PUT-on-collection-root). ONLY the name is updatable; the new name must be ' +
        'globally unique (else EKU-004). Standard/default EKUs cannot be updated ' +
        '(EKU-005); an unknown oid returns EKU-003.\nSafety tier: mutating-safe\n' +
        'MANDATORY fields: oid (lookup key — identifies which EKU to update) and ' +
        'name (the new value). Ask the user for both — never infer them, especially ' +
        'the oid, which is the immutable identifier of the target EKU.',
      inputSchema: z.object({
        oid: z
          .string()
          .min(1)
          .describe(
            'OID of the custom EKU to update (lookup key; immutable). Ask the user — never infer.',
          ),
        name: z
          .string()
          .min(1)
          .describe(
            'New display name (globally unique across all EKUs). Ask the user — never infer.',
          ),
      }),
    },
    async ({ oid, name }) => {
      // `custom` is mandatory on the wire (Stream's play-json Reads has no
      // default), even though only `name` is actually updated server-side and
      // the OID must already belong to a custom EKU. Omitting it returns 400
      // EKU-002 "/custom: error.path.missing". Send custom:true.
      const result = await client.put<Record<string, unknown>>(
        '/api/v1/extension/ekus',
        { oid, name, custom: true },
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'eku',
          name: oid,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  registerDeleteTool(server, client, EKU_SPEC, {
    description:
      'Delete a custom Extended Key Usage by OID. Standard/default EKUs cannot be ' +
      'deleted (EKU-005).',
    deleteConstraints:
      'Fails (EKU-006) if the EKU is referenced by any certificate template — ' +
      'remove those references first.',
  });
}
