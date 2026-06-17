/**
 * Shared scaffolding for Stream name-keyed configuration CRUD tools.
 *
 * Each domain object declares its Zod input schemas + payload mapping, then
 * calls the register helpers here to wire create/read/update/delete. The
 * scaffold owns the boilerplate that is identical across objects:
 *   - response envelopes (buildMutateResponse / buildListResponse)
 *   - the GET-strip-merge-PUT update cycle with an EXPLICIT per-object strip set
 *     (Stream's PUT-on-collection-root, full-replace, keyed by the body id field)
 *   - the delete safety echo (deleteGuard)
 *   - "never assume" guidance: mandatory fields are required Zod params and the
 *     description tells the model to ask the user rather than infer.
 *
 * Two object shapes are supported:
 *   - FLAT / fully-typed: every field is a typed Zod param (preferred).
 *   - COMPLEX / polymorphic: a `describe_<noun>_schema` tool surfaces the audited
 *     structure, and create/update take typed mandatory params + a validated
 *     `config` body (assertConfigBody) so the model never guesses (used for
 *     polymorphic objects like CAs, keystores, triggers).
 *
 * Contracts are grounded in docs/audit/<domain>.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../client/errors.js';
import type { StreamClient } from '../client/http.js';
import {
  buildListResponse,
  buildMutateResponse,
  deleteGuard,
  encodePathSegment,
} from './helpers.js';
import { registerTool } from './register.js';

export const MAX_LIST_ITEMS = 50;

export interface ConfigSpec {
  /** Singular noun for tool names + messages, e.g. "ocsp_signer". */
  readonly noun: string;
  /** Plural noun for the list tool name, e.g. "ocsp_signers". */
  readonly nounPlural: string;
  /** Human label, e.g. "OCSP signer". */
  readonly label: string;
  /** Collection route, e.g. "/api/v1/ocsp/signers". */
  readonly routeCollection: string;
  /** Item route template, e.g. "/api/v1/ocsp/signers/{name}". Omit for singletons. */
  readonly routeItem?: string;
  /** Primary-key field name (usually "name"). Omit for singletons. */
  readonly idField?: string;
  /** Immutable keys (primary key + any server-immutable fields). */
  readonly immutableKeys: readonly string[];
  /**
   * Server-managed / asymmetric fields to strip before a PUT. MUST include any
   * field that is rich-on-read but written differently (e.g. `certificate`,
   * `publicKey`), plus server-computed fields - the server restores or
   * recomputes them.
   */
  readonly stripFields: readonly string[];
  /**
   * When true the update PUT targets the COLLECTION route (Stream's body-keyed
   * full-replace). When false it targets the item route. Stream uses true.
   */
  readonly putOnCollection: boolean;
  /** Optional knowledge-resource reference for the description footer. */
  readonly knowledgeRef?: string;
}

function refFooter(spec: ConfigSpec): string {
  return spec.knowledgeRef ? `\n\nRef: ${spec.knowledgeRef}.` : '';
}

/** Resolve the item path for a given id, encoding the id segment. */
function itemPath(spec: ConfigSpec, id: string): string {
  if (!spec.routeItem) {
    throw new StreamError(500, {
      errorCode: 'CONFIG-NO-ITEM-ROUTE',
      message: `${spec.label} has no item route (singleton).`,
    });
  }
  const placeholders = spec.routeItem.match(/\{[^}]+\}/g) ?? [];
  if (placeholders.length !== 1) {
    throw new StreamError(500, {
      errorCode: 'CONFIG-ITEM-ROUTE',
      message: `${spec.label} item route must have exactly one path placeholder.`,
    });
  }
  return spec.routeItem.replace(/\{[^}]+\}/, encodePathSegment(id));
}

export function immutableNote(spec: ConfigSpec): string {
  const key = spec.idField ?? 'name';
  return (
    `IMPORTANT: ${key} is an immutable primary key and cannot be changed after ` +
    `creation. Always ask the user for it before creating - never invent or infer it.`
  );
}

export function mandatoryNote(fields: readonly string[]): string {
  if (fields.length === 0) return '';
  return (
    `MANDATORY fields: ${fields.join(', ')}. If the user has not supplied one of ` +
    `these, DO NOT infer or default it - ask the user for the value.`
  );
}

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// ---------------------------------------------------------------------------
// GET-strip-merge-PUT with explicit strip set
// ---------------------------------------------------------------------------

export async function getStripMergePutExplicit(
  client: StreamClient,
  getPath: string,
  putPath: string,
  stripFields: readonly string[],
  overrides: Record<string, unknown>,
  clearFields?: string[],
): Promise<Record<string, unknown>> {
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
  const strip = new Set(stripFields);
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(current)) {
    if (!strip.has(k)) payload[k] = v;
  }
  for (const f of clearFields ?? []) payload[f] = null;
  for (const [k, v] of Object.entries(overrides)) {
    if (v !== undefined) payload[k] = v;
  }
  return client.put<Record<string, unknown>>(putPath, payload);
}

// ---------------------------------------------------------------------------
// Read tools (list + get)
// ---------------------------------------------------------------------------

export function registerReadTools(
  server: McpServer,
  client: StreamClient,
  spec: ConfigSpec,
  opts: { listDescription: string; getDescription?: string },
): void {
  registerTool(
    server,
    `list_${spec.nounPlural}`,
    {
      description: `${opts.listDescription}\nSafety tier: read-only${refFooter(spec)}`,
      inputSchema: z.object({
        max_items: z
          .number()
          .int()
          .positive()
          .max(100)
          .default(MAX_LIST_ITEMS)
          .describe('Maximum items to return (default 50).'),
        name_contains: z
          .string()
          .optional()
          .describe(
            `Case-insensitive substring filter on ${spec.idField ?? 'name'}.`,
          ),
      }),
    },
    async ({ max_items, name_contains }) => {
      // Stream returns 204 for empty/forbidden collections -> getList maps to [].
      const items = await client.getList<Record<string, unknown>>(
        spec.routeCollection,
      );
      const field = spec.idField ?? 'name';
      const needle = name_contains?.toLowerCase();
      const filtered = items.filter((item) => {
        if (!needle) return true;
        const v = item[field];
        return typeof v === 'string' && v.toLowerCase().includes(needle);
      });
      return text(buildListResponse(filtered, max_items, spec.noun));
    },
  );

  if (spec.routeItem && spec.idField) {
    const idField = spec.idField;
    registerTool(
      server,
      `get_${spec.noun}`,
      {
        description:
          `${opts.getDescription ?? `Get a single ${spec.label} by ${idField}.`}` +
          `\nSafety tier: read-only${refFooter(spec)}`,
        inputSchema: z.object({
          [idField]: z.string().describe(`Exact ${spec.label} ${idField}.`),
        }),
      },
      async (args: Record<string, unknown>) => {
        const id = String(args[idField]);
        const result = await client.get(itemPath(spec, id));
        return text(JSON.stringify(result));
      },
    );
  }
}

// ---------------------------------------------------------------------------
// Create tool
// ---------------------------------------------------------------------------

export function registerCreateTool<S extends z.ZodObject<z.ZodRawShape>>(
  server: McpServer,
  client: StreamClient,
  spec: ConfigSpec,
  opts: {
    description: string;
    mandatoryFields: readonly string[];
    inputSchema: S;
    buildPayload: (args: z.infer<S>) => Record<string, unknown>;
    preValidate?: (args: z.infer<S>) => string | undefined;
    /** One-time secret fields to return in clear (e.g. a generated password). */
    revealFields?: readonly string[];
  },
): void {
  registerTool(
    server,
    `create_${spec.noun}`,
    {
      description: `${opts.description}\nSafety tier: mutating-safe\n${immutableNote(
        spec,
      )}\n${mandatoryNote(opts.mandatoryFields)}${refFooter(spec)}`,
      inputSchema: opts.inputSchema,
    },
    async (args: z.infer<S>) => {
      const err = opts.preValidate?.(args);
      if (err !== undefined) return text(err);
      const body = opts.buildPayload(args);
      const result = await client.post<Record<string, unknown>>(
        spec.routeCollection,
        body,
      );
      const name = String(
        (body as Record<string, unknown>)[spec.idField ?? 'name'] ?? '',
      );
      return text(
        buildMutateResponse({
          action: 'created',
          kind: spec.noun,
          name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
          reveal: opts.revealFields,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// Update tool
// ---------------------------------------------------------------------------

export function registerUpdateTool<S extends z.ZodObject<z.ZodRawShape>>(
  server: McpServer,
  client: StreamClient,
  spec: ConfigSpec,
  opts: {
    description: string;
    inputSchema: S;
    buildOverrides: (args: z.infer<S>) => Record<string, unknown>;
    preValidate?: (args: z.infer<S>) => string | undefined;
  },
): void {
  const idField = spec.idField ?? 'name';
  registerTool(
    server,
    `update_${spec.noun}`,
    {
      description:
        `${opts.description}\nSafety tier: mutating-safe\n` +
        `Update is a full-replace done as GET -> strip server fields -> merge your ` +
        `changes -> PUT: any field you OMIT keeps its current value (the tool ` +
        `re-sends it from the existing record). Use clear_fields to explicitly null ` +
        `an optional field. ${immutableNote(spec)}${refFooter(spec)}`,
      inputSchema: opts.inputSchema,
    },
    async (args: z.infer<S>) => {
      const err = opts.preValidate?.(args);
      if (err !== undefined) return text(err);
      const id = String((args as Record<string, unknown>)[idField]);
      const overrides = opts.buildOverrides(args);
      const clearFields = (args as Record<string, unknown>)['clear_fields'] as
        | string[]
        | undefined;
      if (clearFields && clearFields.length > 0) {
        const forbidden = new Set<string>([
          ...spec.stripFields,
          ...spec.immutableKeys,
        ]);
        const bad = clearFields.filter((f) => forbidden.has(f));
        if (bad.length > 0) {
          throw new StreamError(422, {
            errorCode: 'CONFIG-CLEAR-FORBIDDEN',
            message: `clear_fields may not target immutable or server-managed fields: ${bad.join(', ')}.`,
            remediation:
              'Remove these from clear_fields - they cannot be nulled.',
          });
        }
      }
      const putPath = spec.putOnCollection
        ? spec.routeCollection
        : itemPath(spec, id);
      const result = await getStripMergePutExplicit(
        client,
        itemPath(spec, id),
        putPath,
        spec.stripFields,
        overrides,
        clearFields,
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: spec.noun,
          name: id,
          data: result,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// Delete tool
// ---------------------------------------------------------------------------

export function registerDeleteTool(
  server: McpServer,
  client: StreamClient,
  spec: ConfigSpec,
  opts: { description: string; deleteConstraints?: string },
): void {
  const idField = spec.idField ?? 'name';
  registerTool(
    server,
    `delete_${spec.noun}`,
    {
      description:
        `${opts.description}\nSafety tier: mutating-destructive\n` +
        `Requires ${idField} confirmation via expected_${idField}.` +
        `${opts.deleteConstraints ? `\n${opts.deleteConstraints}` : ''}${refFooter(spec)}`,
      inputSchema: z.object({
        [idField]: z.string().describe(`${spec.label} ${idField} to delete.`),
        [`expected_${idField}`]: z
          .string()
          .describe(`Must exactly match ${idField} as a deletion safeguard.`),
      }),
    },
    async (args: Record<string, unknown>) => {
      const id = String(args[idField]);
      const expected = String(args[`expected_${idField}`]);
      deleteGuard(id, expected, idField);
      await client.delete(itemPath(spec, id));
      return text(
        JSON.stringify({ deleted: true, [idField]: id, kind: spec.noun }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// Complex / polymorphic support: describe-schema + validated config body
// ---------------------------------------------------------------------------

export interface ComplexSchemaInfo {
  readonly noun: string;
  readonly label: string;
  readonly discriminatorField?: string;
  readonly subtypes: readonly string[];
  readonly mandatoryFields: readonly string[];
  readonly jsonSchema: unknown;
  readonly schemaVersion: string;
  readonly knowledgeRef?: string;
}

export function registerDescribeSchemaTool(
  server: McpServer,
  info: ComplexSchemaInfo,
): void {
  const foot = info.knowledgeRef ? `\n\nRef: ${info.knowledgeRef}.` : '';
  registerTool(
    server,
    `describe_${info.noun}_schema`,
    {
      description:
        `Return the exact request structure for ${info.label} (subtypes, mandatory ` +
        `fields, enums, full JSON Schema). Call this BEFORE create_${info.noun} or ` +
        `update_${info.noun} so the body matches what Stream expects - never guess ` +
        `the structure.\nSafety tier: read-only${foot}`,
      inputSchema: z.object({
        subtype: z
          .string()
          .optional()
          .describe(
            info.discriminatorField
              ? `Optional ${info.discriminatorField} to narrow the schema to one subtype.`
              : 'Optional subtype to narrow the schema.',
          ),
      }),
    },
    async ({ subtype }) =>
      text(
        JSON.stringify({
          object: info.noun,
          discriminatorField: info.discriminatorField ?? null,
          subtypes: info.subtypes,
          mandatoryFields: info.mandatoryFields,
          schemaVersion: info.schemaVersion,
          requestedSubtype: subtype ?? null,
          jsonSchema: info.jsonSchema,
        }),
      ),
  );
}

/**
 * Lightweight client-side guard for complex bodies. Confirms required keys are
 * present, top-level keys are known, and enum values are valid. Deep validation
 * is delegated to Stream (which returns precise errors the tool surfaces).
 */
export function assertConfigBody(
  body: Record<string, unknown>,
  rules: {
    requiredKeys: readonly string[];
    knownKeys: readonly string[];
    enums?: Record<string, readonly string[]>;
  },
): void {
  const missing = rules.requiredKeys.filter(
    (k) => body[k] === undefined || body[k] === null,
  );
  if (missing.length > 0) {
    throw new StreamError(422, {
      errorCode: 'CONFIG-MISSING-MANDATORY',
      message: `Missing mandatory field(s): ${missing.join(', ')}.`,
      remediation:
        'Ask the user for these values - do not infer them. Call the describe ' +
        'tool to see the full required structure.',
    });
  }
  const known = new Set(rules.knownKeys);
  const unknown = Object.keys(body).filter((k) => !known.has(k));
  if (unknown.length > 0) {
    throw new StreamError(422, {
      errorCode: 'CONFIG-UNKNOWN-FIELD',
      message: `Unknown top-level field(s): ${unknown.join(', ')}.`,
      remediation:
        'Remove these fields. Call the describe tool to see the allowed fields.',
    });
  }
  for (const [field, values] of Object.entries(rules.enums ?? {})) {
    const v = body[field];
    if (v === undefined) continue;
    if (typeof v !== 'string' || !values.includes(v)) {
      throw new StreamError(422, {
        errorCode: 'CONFIG-BAD-ENUM',
        message: `Invalid ${field}=${JSON.stringify(v)}. Allowed: ${values.join(', ')}.`,
      });
    }
  }
}
