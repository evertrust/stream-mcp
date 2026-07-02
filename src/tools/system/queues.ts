/**
 * Queue CRUD (api.queue.Routes). Standard name-keyed scaffold:
 * PUT-on-collection-root full-replace, name immutable, 204->[] on list.
 *
 * Audit: docs/audit/system.md sections 9-13.
 *   Queue = { id (server), name (PK), description?, size>0,
 *             throttleDuration? (FiniteDuration string), throttleParallelism?>0,
 *             clusterWide (required) }.
 *   Quirk: throttleDuration requires throttleParallelism to also be set.
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

const QUEUE_SPEC: ConfigSpec = {
  noun: 'queue',
  nounPlural: 'queues',
  label: 'queue',
  routeCollection: '/api/v1/queues',
  routeItem: '/api/v1/queues/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  stripFields: ['id'],
  putOnCollection: true,
};

// FiniteDuration wire format, e.g. "5 seconds" (matches the server regex,
// trimmed). Used to give a precise client-side error before the round-trip.
const DURATION_RE =
  /^([0-9]+) *(ms|millisecond|milliseconds|s|second|seconds|m|minute|minutes|h|hour|hours|d|day|days)$/;

const createSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe(
      'Queue name (immutable primary key). Ask the user — never infer.',
    ),
  description: z
    .string()
    .optional()
    .describe('Optional free-text description.'),
  size: z
    .number()
    .int()
    .positive()
    .describe('Queue size; must be greater than 0.'),
  throttle_duration: z
    .string()
    .optional()
    .describe(
      'Optional throttle window as a FiniteDuration string, e.g. "1 second", "500 ms", "5 minutes". If set, throttle_parallelism is required.',
    ),
  throttle_parallelism: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('Optional throttle parallelism; must be > 0 if set.'),
  cluster_wide: z
    .boolean()
    .describe('Whether the queue is cluster-wide (required).'),
});

const updateSchema = z.object({
  name: z
    .string()
    .min(1)
    .describe('Name of the queue to update (lookup key; immutable).'),
  description: z
    .string()
    .optional()
    .describe('New description. Omit to keep current (full-replace PUT).'),
  size: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('New size (> 0). Omit to keep current.'),
  throttle_duration: z
    .string()
    .optional()
    .describe(
      'New throttle window, e.g. "1 second". Omit to keep current. If set, throttle_parallelism must also be set.',
    ),
  throttle_parallelism: z
    .number()
    .int()
    .positive()
    .optional()
    .describe('New throttle parallelism (> 0). Omit to keep current.'),
  cluster_wide: z
    .boolean()
    .optional()
    .describe('New cluster-wide flag. Omit to keep current.'),
  clear_fields: z
    .array(z.string())
    .optional()
    .describe(
      'Optional list of optional fields to explicitly null (e.g. ["description","throttleDuration","throttleParallelism"]).',
    ),
});

type CreateArgs = z.infer<typeof createSchema>;
type UpdateArgs = z.infer<typeof updateSchema>;

function validateThrottle(
  duration: string | undefined,
  parallelism: number | undefined,
): string | undefined {
  if (duration !== undefined) {
    if (!DURATION_RE.test(duration.trim())) {
      // Plain message: the scaffold surfaces it as an isError tool result
      // with a CLIENT-VALIDATION structured envelope.
      return (
        `INVALID_THROTTLE_DURATION: throttle_duration='${duration}' is not a ` +
        'valid FiniteDuration. Use a value like "5 seconds", "500 ms", or ' +
        '"1 minute".'
      );
    }
    if (parallelism === undefined) {
      return (
        'THROTTLE_PARALLELISM_REQUIRED: throttle_duration requires ' +
        'throttle_parallelism to also be set (Stream: "Throttle duration ' +
        'must be defined with throttle parallelism").'
      );
    }
  }
  return undefined;
}

export function registerQueueTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, QUEUE_SPEC, {
    listDescription:
      'List configured queues (name, size, clusterWide, optional throttle). Returns an empty list if none are configured or you lack AUDIT permission.',
    getDescription: 'Get a single queue by its exact name.',
  });

  registerCreateTool(server, client, QUEUE_SPEC, {
    description:
      'Create a queue. Queues throttle/serialize work such as CA issuance.',
    mandatoryFields: ['name', 'size', 'cluster_wide'],
    inputSchema: createSchema,
    preValidate: (args: CreateArgs) =>
      validateThrottle(args.throttle_duration, args.throttle_parallelism),
    buildPayload: (args: CreateArgs) => {
      const body: Record<string, unknown> = {
        name: args.name,
        size: args.size,
        clusterWide: args.cluster_wide,
      };
      if (args.description !== undefined)
        body['description'] = args.description;
      if (args.throttle_duration !== undefined)
        body['throttleDuration'] = args.throttle_duration;
      if (args.throttle_parallelism !== undefined)
        body['throttleParallelism'] = args.throttle_parallelism;
      return body;
    },
  });

  registerUpdateTool(server, client, QUEUE_SPEC, {
    description:
      'Update a queue (full-replace by name). Any optional field you OMIT keeps its current value (the tool re-sends it from the existing record); use clear_fields to explicitly null an optional field.',
    inputSchema: updateSchema,
    preValidate: (args: UpdateArgs) =>
      validateThrottle(args.throttle_duration, args.throttle_parallelism),
    buildOverrides: (args: UpdateArgs) => ({
      description: args.description,
      size: args.size,
      throttleDuration: args.throttle_duration,
      throttleParallelism: args.throttle_parallelism,
      clusterWide: args.cluster_wide,
    }),
  });

  registerDeleteTool(server, client, QUEUE_SPEC, {
    description: 'Delete a queue by name.',
    deleteConstraints:
      'Fails (QUEUE-005) if any managed X509 CA references this queue — repoint those CAs first.',
  });
}
