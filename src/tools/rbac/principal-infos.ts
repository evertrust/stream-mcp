/**
 * Principal infos (authorizations): identifier-keyed. NO list endpoint - use
 * search_principal_infos (POST) instead. Permissions follow the same grammar as
 * roles; roles[] must reference existing role names.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
  registerDeleteTool,
} from '../_scaffold.js';
import {
  buildMutateResponse,
  buildSearchResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';
import { PERMISSION_GRAMMAR, toPermissionObjects } from './permissions.js';

const ROUTE = '/api/v1/security/principalinfos';

const SPEC: ConfigSpec = {
  noun: 'principal_info',
  nounPlural: 'principal_infos',
  label: 'principal info',
  routeCollection: ROUTE,
  routeItem: `${ROUTE}/{identifier}`,
  idField: 'identifier',
  immutableKeys: ['identifier'],
  // id + the three server-managed timestamps are preserved/recomputed server-side.
  stripFields: ['id', 'creationDate', 'lastAuthentication', 'lastModification'],
  putOnCollection: true,
};

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const SORTABLE = ['identifier', 'role'] as const;

export function registerPrincipalInfoTools(
  server: McpServer,
  client: StreamClient,
): void {
  // get (custom; no list endpoint exists for this resource)
  registerTool(
    server,
    'get_principal_info',
    {
      description:
        'Get a single principal info (authorizations) by identifier. There is ' +
        'NO list endpoint - use search_principal_infos to enumerate.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        identifier: z.string().describe('Exact principal identifier.'),
      }),
    },
    async ({ identifier }) => {
      const result = await client.get(
        `${ROUTE}/${encodePathSegment(identifier)}`,
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'create_principal_info',
    {
      description:
        'Create a principal info: direct permissions + role assignments for an ' +
        'identity. Cannot create your OWN principal info (403). roles[] must ' +
        'reference existing role names.\nSafety tier: mutating-safe\n' +
        'IMPORTANT: identifier is an immutable key - ask the user; never invent it.\n' +
        PERMISSION_GRAMMAR,
      inputSchema: z.object({
        identifier: z
          .string()
          .describe('Immutable principal identifier (primary key).'),
        permissions: z
          .array(z.string())
          .optional()
          .describe('Direct permission strings (see grammar).'),
        roles: z
          .array(z.string())
          .optional()
          .describe('Role names to assign (must already exist).'),
      }),
    },
    async (args) => {
      const body: Record<string, unknown> = { identifier: args.identifier };
      const perms = toPermissionObjects(args.permissions);
      if (perms !== undefined) body['permissions'] = perms;
      if (args.roles !== undefined) body['roles'] = args.roles;
      const result = await client.post<Record<string, unknown>>(ROUTE, body);
      return text(
        buildMutateResponse({
          action: 'created',
          kind: SPEC.noun,
          name: args.identifier,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  registerTool(
    server,
    'update_principal_info',
    {
      description:
        'Update a principal info (full-replace via PUT, lookup by identifier; ' +
        'omitted optional fields are reset). Cannot edit your OWN principal ' +
        'info (403).\nSafety tier: mutating-safe\nIMPORTANT: identifier is immutable.\n' +
        PERMISSION_GRAMMAR,
      inputSchema: z.object({
        identifier: z
          .string()
          .describe(
            'Identifier of the principal info to update (immutable key).',
          ),
        permissions: z
          .array(z.string())
          .optional()
          .describe('Full replacement permission-string list.'),
        roles: z
          .array(z.string())
          .optional()
          .describe('Full replacement role-name list (must exist).'),
        clear_fields: z
          .array(z.string())
          .optional()
          .describe('Optional fields to null out (e.g. permissions, roles).'),
      }),
    },
    async (args) => {
      const overrides: Record<string, unknown> = {};
      const perms = toPermissionObjects(args.permissions);
      if (perms !== undefined) overrides['permissions'] = perms;
      if (args.roles !== undefined) overrides['roles'] = args.roles;
      const clearFields = args.clear_fields;
      if (clearFields && clearFields.length > 0) {
        const forbidden = new Set<string>([
          ...SPEC.stripFields,
          ...SPEC.immutableKeys,
        ]);
        const bad = clearFields.filter((f) => forbidden.has(f));
        if (bad.length > 0) {
          throw new StreamError(422, {
            errorCode: 'CONFIG-CLEAR-FORBIDDEN',
            message: `clear_fields may not target immutable or server-managed fields: ${bad.join(', ')}.`,
          });
        }
      }
      const result = await getStripMergePutExplicit(
        client,
        `${ROUTE}/${encodePathSegment(args.identifier)}`,
        ROUTE,
        SPEC.stripFields,
        overrides,
        clearFields,
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: SPEC.noun,
          name: args.identifier,
          data: result,
        }),
      );
    },
  );

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete a principal info by identifier. Cannot delete your OWN principal info (403).',
  });

  // search (POST; the only way to enumerate principal infos)
  registerTool(
    server,
    'search_principal_infos',
    {
      description:
        'Search principal infos (POST). All filters optional - an empty body ' +
        'returns all, paged. This REPLACES a list endpoint (none exists).\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        identifier: z
          .string()
          .optional()
          .describe(
            'Substring match on identifier (regex-quoted server-side).',
          ),
        role: z.string().optional().describe('Filter by role name.'),
        strict_search: z.boolean().optional().describe('Strict-match toggle.'),
        sorted_by: z
          .enum(SORTABLE)
          .optional()
          .describe('Sort element: identifier or role.'),
        sort_direction: z
          .enum(['ASC', 'DESC'])
          .optional()
          .describe('Sort direction (default ASC). Applies to sorted_by.'),
        page_index: z
          .number()
          .int()
          .positive()
          .optional()
          .describe('1-based page index.'),
        page_size: z.number().int().positive().max(100).optional(),
        with_count: z
          .boolean()
          .optional()
          .describe('Include total count in the response.'),
      }),
    },
    async (args) => {
      const pageIndex = args.page_index ?? 1;
      const pageSize = args.page_size ?? 20;
      const body: Record<string, unknown> = {
        pageIndex,
        pageSize,
      };
      if (args.identifier !== undefined) body['identifier'] = args.identifier;
      if (args.role !== undefined) body['role'] = args.role;
      if (args.strict_search !== undefined)
        body['strictSearch'] = args.strict_search;
      if (args.sorted_by !== undefined) {
        // Wire shape is SortElement{element, order} with SortOrder entryNames
        // "Asc"/"Desc" (PascalCase, case-sensitive). The user-facing ASC/DESC
        // input is mapped to the on-the-wire enum value.
        body['sortedBy'] = [
          {
            element: args.sorted_by,
            order: args.sort_direction === 'DESC' ? 'Desc' : 'Asc',
          },
        ];
      }
      if (args.with_count !== undefined) body['withCount'] = args.with_count;

      const result = await client.post<Record<string, unknown>>(
        `${ROUTE}/search`,
        body,
      );
      const normalized = buildSearchResponse(
        (result ?? {}) as Record<string, unknown>,
        pageIndex,
        pageSize,
      );
      return text(JSON.stringify(normalized));
    },
  );
}
