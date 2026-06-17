/**
 * Roles: name-keyed configuration object with a list of permission strings.
 * Read/delete via the scaffold; create/update map snake_case inputs to the
 * `{value}` permission wire shape.
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
import { PERMISSION_GRAMMAR, toPermissionObjects } from './permissions.js';

const SPEC: ConfigSpec = {
  noun: 'role',
  nounPlural: 'roles',
  label: 'role',
  routeCollection: '/api/v1/security/roles',
  routeItem: '/api/v1/security/roles/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  // id is server-managed; permissions are rich-on-read ({value} objects) but we
  // rewrite the full permissions array on every update, so stripping is fine.
  stripFields: ['id'],
  putOnCollection: true,
};

export function registerRoleTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List all roles (name + permission strings). Roles bundle reusable ' +
      'permission sets that principal infos can reference by name.',
    getDescription: 'Get a single role by name, including its permissions.',
  });

  registerCreateTool(server, client, SPEC, {
    description:
      'Create a role: a named bundle of permission strings.\n' +
      PERMISSION_GRAMMAR,
    mandatoryFields: ['name'],
    inputSchema: z.object({
      name: z.string().describe('Immutable role name (primary key).'),
      description: z
        .string()
        .optional()
        .describe('Optional human description.'),
      permissions: z
        .array(z.string())
        .optional()
        .describe(
          'Permission strings (see grammar). Server dedupes + sorts them. ' +
            'Lifecycle CAs/templates must already exist.',
        ),
    }),
    buildPayload: (args) => {
      const body: Record<string, unknown> = { name: args.name };
      if (args.description !== undefined)
        body['description'] = args.description;
      const perms = toPermissionObjects(args.permissions);
      if (perms !== undefined) body['permissions'] = perms;
      return body;
    },
  });

  registerUpdateTool(server, client, SPEC, {
    description:
      'Update a role. Any optional field you OMIT keeps its current value (the ' +
      'tool fetches the existing record and merges your changes); use ' +
      'clear_fields to explicitly null an optional field (e.g. description).\n' +
      PERMISSION_GRAMMAR,
    inputSchema: z.object({
      name: z.string().describe('Role name to update (immutable key).'),
      description: z.string().optional().describe('New description.'),
      permissions: z
        .array(z.string())
        .optional()
        .describe('Full replacement permission-string list.'),
      clear_fields: z
        .array(z.string())
        .optional()
        .describe('Optional fields to null out (e.g. description).'),
    }),
    buildOverrides: (args) => {
      const overrides: Record<string, unknown> = {};
      if (args.description !== undefined)
        overrides['description'] = args.description;
      const perms = toPermissionObjects(args.permissions);
      if (perms !== undefined) overrides['permissions'] = perms;
      return overrides;
    },
  });

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete a role by name. Also removes the role from every principal info ' +
      'that references it.',
  });
}
