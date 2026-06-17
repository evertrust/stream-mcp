/**
 * Local identities: identifier-keyed local accounts. The server owns the
 * password (generated on create, regenerated on reset) and the crypt hash;
 * neither is ever accepted in a write body.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  registerCreateTool,
  registerDeleteTool,
  registerReadTools,
  registerUpdateTool,
} from '../_scaffold.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';

const ROUTE = '/api/v1/security/identity/locals';

const SPEC: ConfigSpec = {
  noun: 'local_identity',
  nounPlural: 'local_identities',
  label: 'local identity',
  routeCollection: ROUTE,
  routeItem: `${ROUTE}/{identifier}`,
  idField: 'identifier',
  immutableKeys: ['identifier'],
  // id, hash and password are server-managed write-only/output-only fields;
  // never echo them back in a PUT.
  stripFields: ['id', 'hash', 'password'],
  putOnCollection: true,
};

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

export function registerLocalIdentityTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List local identities (identifier + display name). Passwords and hashes ' +
      'are never returned.',
    getDescription:
      'Get a single local identity by identifier (no password/hash).',
  });

  registerCreateTool(server, client, SPEC, {
    description:
      'Create a local identity. The server GENERATES the password (you cannot ' +
      'set it); it is returned ONCE in the response. Requires an enabled Local ' +
      'identity provider to exist.',
    mandatoryFields: ['identifier'],
    inputSchema: z.object({
      identifier: z
        .string()
        .describe(
          'Immutable account identifier (primary key). No leading/trailing whitespace.',
        ),
      name: z.string().optional().describe('Optional display name.'),
      expires: z
        .string()
        .optional()
        .describe('Optional ISO-8601 account expiry instant.'),
    }),
    buildPayload: (args) => {
      const body: Record<string, unknown> = { identifier: args.identifier };
      if (args.name !== undefined) body['name'] = args.name;
      if (args.expires !== undefined) body['expires'] = args.expires;
      return body;
    },
    // The server-generated one-time password is the point of create — return it
    // in clear (it is otherwise redacted) so the caller can capture it once.
    revealFields: ['password'],
  });

  registerUpdateTool(server, client, SPEC, {
    description:
      'Update a local identity (full-replace of optional fields). The password ' +
      'CANNOT be changed here - use reset_local_identity_password.',
    inputSchema: z.object({
      identifier: z
        .string()
        .describe(
          'Identifier of the local identity to update (immutable key).',
        ),
      name: z.string().optional().describe('New display name.'),
      expires: z.string().optional().describe('New ISO-8601 expiry instant.'),
      clear_fields: z
        .array(z.string())
        .optional()
        .describe('Optional fields to null out (e.g. name, expires).'),
    }),
    buildOverrides: (args) => {
      const overrides: Record<string, unknown> = {};
      if (args.name !== undefined) overrides['name'] = args.name;
      if (args.expires !== undefined) overrides['expires'] = args.expires;
      return overrides;
    },
  });

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete a local identity by identifier. Self-delete is forbidden by the server.',
  });

  // Custom: GET resetpassword -> regenerates a random password, returned once.
  registerTool(
    server,
    'reset_local_identity_password',
    {
      description:
        'Reset a local identity password. The server GENERATES a new random ' +
        'password and returns it ONCE - capture it immediately. Self password ' +
        'reset is forbidden by the server.\nSafety tier: mutating-safe',
      inputSchema: z.object({
        identifier: z
          .string()
          .describe(
            'Identifier of the local identity whose password to reset.',
          ),
      }),
    },
    async ({ identifier }) => {
      const id = String(identifier);
      if (!id.trim()) {
        throw new StreamError(422, {
          errorCode: 'LOCAL-ID-VALIDATION',
          message: 'identifier must not be blank.',
        });
      }
      const result = await client.get<Record<string, unknown>>(
        `${ROUTE}/${encodePathSegment(id)}/resetpassword`,
      );
      return text(
        buildMutateResponse({
          action: 'password_reset',
          kind: SPEC.noun,
          name: id,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
          // Return the one-time generated password in clear (it is the purpose
          // of this call); it is otherwise stripped by secret redaction.
          reveal: ['password'],
        }),
      );
    },
  );
}
