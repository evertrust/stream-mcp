/**
 * System configuration entries (api.system.configuration.Routes).
 *
 * NOT a standard name-keyed object: entries are keyed by `type`
 * (license | internal_monitor). There is no POST/DELETE — the only write is a
 * PUT-as-upsert on the collection root, keyed on the body `type`:
 *   - found    -> full-replace (200), reuses the existing id
 *   - not found-> create (201)
 * The body is polymorphic, discriminated by `type`. `id` is server-managed.
 *
 * Audit: docs/audit/system.md sections 1-3.
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  buildListResponse,
  buildMutateResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';
import { SYSTEM_CONFIGURATION_TYPES } from './enums.js';

const ROUTE = '/api/v1/system/configuration';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const typeEnum = z.enum(SYSTEM_CONFIGURATION_TYPES);

// Polymorphic upsert body, discriminated by `type`.
//   license          : optional triggers.onLicenseExpiration (string[] of trigger names)
//   internal_monitor : required cron (Quartz cron string)
const licenseSchema = z.object({
  type: z.literal('license'),
  on_license_expiration: z
    .array(z.string())
    .optional()
    .describe(
      'Names of pre-existing triggers fired on license expiration (LicenseTriggers.onLicenseExpiration). Omit for no triggers.',
    ),
});

const internalMonitorSchema = z.object({
  type: z.literal('internal_monitor'),
  cron: z
    .string()
    .min(1)
    .describe(
      'Quartz cron expression for the internal monitor, e.g. "0 0 0 ? * * *". Required.',
    ),
});

const upsertSchema = z.object({
  config: z
    .discriminatedUnion('type', [licenseSchema, internalMonitorSchema])
    .describe(
      'The system configuration entry to upsert, discriminated by type (license | internal_monitor).',
    ),
});

type UpsertConfig = z.infer<typeof upsertSchema>['config'];

function buildUpsertBody(config: UpsertConfig): Record<string, unknown> {
  if (config.type === 'license') {
    const body: Record<string, unknown> = { type: 'license' };
    if (config.on_license_expiration !== undefined) {
      body['triggers'] = { onLicenseExpiration: config.on_license_expiration };
    }
    return body;
  }
  // internal_monitor
  return { type: 'internal_monitor', cron: config.cron };
}

export function registerSystemConfigurationTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'list_system_configuration',
    {
      description:
        'List all configured system configuration entries (one per type: license, internal_monitor). ' +
        'Each entry is discriminated by `type`. Returns an empty list if none are configured or you lack AUDIT permission.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({}),
    },
    async () => {
      const items = await client.getList<Record<string, unknown>>(ROUTE);
      return text(
        buildListResponse(items, items.length, 'system_configuration'),
      );
    },
  );

  registerTool(
    server,
    'get_system_configuration',
    {
      description:
        'Get a single system configuration entry by its type. 404 (SYS-CONF-003) if that type has no stored entry.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        type: typeEnum.describe(
          'The configuration entry type: license or internal_monitor.',
        ),
      }),
    },
    async ({ type }) => {
      const result = await client.get(`${ROUTE}/${encodePathSegment(type)}`);
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'upsert_system_configuration',
    {
      description:
        'Create or update a system configuration entry. Keyed by `type` (NOT id): if an entry of the same type exists it is full-replaced (reusing its id), otherwise it is created. ' +
        'There is no separate create/delete — this PUT is the only write.\n' +
        'For type=internal_monitor, `cron` is REQUIRED (Quartz cron). For type=license, triggers are optional.\n' +
        'Safety tier: mutating-safe (idempotent upsert)',
      inputSchema: upsertSchema,
    },
    async ({ config }) => {
      // Defensive: discriminatedUnion already guarantees this, but guard the
      // wire contract explicitly.
      if (!SYSTEM_CONFIGURATION_TYPES.includes(config.type)) {
        throw new StreamError(422, {
          errorCode: 'CONFIG-BAD-ENUM',
          message: `Invalid type. Allowed: ${SYSTEM_CONFIGURATION_TYPES.join(', ')}.`,
        });
      }
      const body = buildUpsertBody(config);
      const result = await client.put<Record<string, unknown>>(ROUTE, body);
      return text(
        buildMutateResponse({
          action: 'upserted',
          kind: 'system_configuration',
          name: config.type,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );
}
