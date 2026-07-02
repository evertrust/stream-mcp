/**
 * Triggers / notifications domain (Stream 2.1).
 *
 * A trigger is a polymorphic config object (`type` = email | rest |
 * external_rl_storage). These tools cover the EMAIL and REST notification
 * families in full; EXTERNAL_RL_STORAGE shares the CRUD endpoints but its
 * per-storageType fields are owned by the RL-storage domain (list_triggers
 * still surfaces them; create/update/test reject them).
 *
 * Endpoints (docs/audit/triggers.md):
 *   GET    /api/v1/triggers              (optional repeatable ?types=)
 *   GET    /api/v1/triggers/{name}
 *   POST   /api/v1/triggers
 *   PUT    /api/v1/triggers              (body.name = key, full-replace)
 *   DELETE /api/v1/triggers/{name}
 *   PATCH  /api/v1/triggers              ({ trigger, dictionary? }) — dry-run
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { redactSensitive, redactValue } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  buildListResponse,
  buildMutateResponse,
  deleteGuard,
  encodePathSegment,
  redactedJson,
} from '../helpers.js';
import { registerTool } from '../register.js';
import { TRIGGER_TYPES } from './enums.js';
import {
  buildTriggerPayload,
  triggerInputSchema,
  validateTrigger,
} from './schema.js';

const ROUTE = '/api/v1/triggers';
const KNOWLEDGE_REF = 'docs/audit/triggers.md';
const MAX_LIST_ITEMS = 50;

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// Request/response header names whose value is a credential. test_trigger's
// REST response echoes back the headers Stream SENT (incl. the Authorization
// header it built from the referenced credential), so redact those values.
const SENSITIVE_HEADER_RE =
  /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-api-secret)$/i;

/**
 * Scrub a test_trigger result before returning it to the model: redact named
 * secret fields, scrub reflected request/response bodies, and blank the values
 * of credential-bearing headers. Returns a fresh object (redactSensitive copies).
 */
function scrubTestResult(result: unknown): Record<string, unknown> {
  const r = redactSensitive(result) as Record<string, unknown>;
  for (const key of ['requestPayload', 'responsePayload']) {
    if (typeof r[key] === 'string') r[key] = redactValue(r[key] as string);
  }
  for (const key of ['requestHeaders', 'responseHeaders']) {
    const hdrs = r[key];
    if (!Array.isArray(hdrs)) continue;
    r[key] = hdrs.map((h) => {
      if (h && typeof h === 'object' && !Array.isArray(h)) {
        const name = (h as Record<string, unknown>)['name'];
        if (typeof name === 'string' && SENSITIVE_HEADER_RE.test(name)) {
          return { ...(h as Record<string, unknown>), value: '<redacted>' };
        }
      }
      return h;
    });
  }
  return r;
}

export function registerTriggerTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerListTriggers(server, client);
  registerGetTrigger(server, client);
  registerCreateTrigger(server, client);
  registerUpdateTrigger(server, client);
  registerDeleteTrigger(server, client);
  registerTestTrigger(server, client);
}

// ---------------------------------------------------------------------------
// list_triggers
// ---------------------------------------------------------------------------

function registerListTriggers(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'list_triggers',
    {
      description:
        'List notification triggers, optionally filtered by type (repeatable ' +
        'OR-filter). Returns the polymorphic trigger objects (email / rest / ' +
        'external_rl_storage).\nSafety tier: read-only\n\nRef: ' +
        `${KNOWLEDGE_REF}.`,
      inputSchema: z.object({
        types: z
          .array(z.enum(TRIGGER_TYPES))
          .optional()
          .describe('Filter to these trigger types (OR). Omit for all types.'),
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
          .describe('Case-insensitive substring filter on name.'),
      }),
    },
    async ({ types, max_items, name_contains }) => {
      let params: URLSearchParams | undefined;
      if (types && types.length > 0) {
        params = new URLSearchParams();
        for (const t of types) params.append('types', t);
      }
      const items = await client.getList<Record<string, unknown>>(
        ROUTE,
        params,
      );
      const needle = name_contains?.toLowerCase();
      const filtered = items.filter((item) => {
        if (!needle) return true;
        const v = item['name'];
        return typeof v === 'string' && v.toLowerCase().includes(needle);
      });
      return text(buildListResponse(filtered, max_items, 'trigger'));
    },
  );
}

// ---------------------------------------------------------------------------
// get_trigger
// ---------------------------------------------------------------------------

function registerGetTrigger(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'get_trigger',
    {
      description:
        'Get a single notification trigger by name.\nSafety tier: read-only' +
        `\n\nRef: ${KNOWLEDGE_REF}.`,
      inputSchema: z.object({
        name: z.string().describe('Exact trigger name (case-sensitive).'),
      }),
    },
    async ({ name }) => {
      const result = await client.get(`${ROUTE}/${encodePathSegment(name)}`);
      return text(redactedJson(result));
    },
  );
}

// ---------------------------------------------------------------------------
// create_trigger
// ---------------------------------------------------------------------------

function registerCreateTrigger(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'create_trigger',
    {
      description:
        'Create an EMAIL or REST notification trigger.\n' +
        'MANDATORY (always): type, name, event. Ask the user for these; do not ' +
        'infer or invent them — especially name, which is the immutable primary ' +
        'key (no spaces; cannot be changed after creation).\n' +
        'MANDATORY for type=email: template.from, template.title, ' +
        'template.is_html. Ask the user; do not infer.\n' +
        'MANDATORY for type=rest: authentication_type, method, url, ' +
        'expected_http_codes (non-empty). Ask the user; do not infer.\n' +
        'CONDITIONAL: run_period is REQUIRED for expiration events ' +
        '(on_*_expiration) and FORBIDDEN otherwise; ask the user for the period. ' +
        'For REST, noauth FORBIDS credentials while basic/bearer/custom/x509 ' +
        'REQUIRE matching credentials (basic->Password, bearer->Raw, ' +
        'custom->Password|Raw, x509->X509).\n' +
        'All other fields are optional.\nSafety tier: mutating-safe\n\nRef: ' +
        `${KNOWLEDGE_REF}.`,
      inputSchema: triggerInputSchema,
    },
    async (args) => {
      validateTrigger(args);
      const body = buildTriggerPayload(args);
      const result = await client.post<Record<string, unknown>>(ROUTE, body);
      return text(
        buildMutateResponse({
          action: 'created',
          kind: 'trigger',
          name: args.name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// update_trigger (PUT on collection root, full-replace; type immutable)
// ---------------------------------------------------------------------------

function registerUpdateTrigger(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'update_trigger',
    {
      description:
        'Full-replace update of an EMAIL or REST trigger.\n' +
        'MANDATORY lookup key: name (the body name identifies which existing ' +
        'trigger to replace; PUT on the collection root, no path id). Ask the ' +
        'user for the exact name; do not infer or invent it — name is immutable ' +
        'and cannot be changed by this call.\n' +
        'FULL-REPLACE: this REPLACES the stored trigger entirely. Any optional ' +
        'field you OMIT is CLEARED/reset (there is no partial-merge / PATCH and ' +
        'no clear_fields mechanism) — supply the COMPLETE desired object, ' +
        'including all per-type mandatory fields (email: template.from/title/' +
        'is_html; rest: authentication_type, method, url, expected_http_codes).\n' +
        'type is IMMUTABLE (cannot change email<->rest for the same name; server ' +
        'returns 500 TRIGGER-001). Same run_period / credentials / ' +
        'expected_http_codes rules as create. Ask the user for any value you do ' +
        'not have; do not infer.\nSafety tier: mutating-safe\n\nRef: ' +
        `${KNOWLEDGE_REF}.`,
      inputSchema: triggerInputSchema,
    },
    async (args) => {
      validateTrigger(args);
      const body = buildTriggerPayload(args);
      const result = await client.put<Record<string, unknown>>(ROUTE, body);
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: 'trigger',
          name: args.name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );
}

// ---------------------------------------------------------------------------
// delete_trigger (echo guard)
// ---------------------------------------------------------------------------

function registerDeleteTrigger(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'delete_trigger',
    {
      description:
        'Delete a notification trigger by name.\nSafety tier: ' +
        'mutating-destructive\nRequires name confirmation via expected_name. ' +
        'Blocked (403 TRIGGER-005) if the trigger is referenced by a CA / SSH ' +
        "CA / OCSP / TSA signer / credentials / system config / another trigger's " +
        `onTriggerError list.\n\nRef: ${KNOWLEDGE_REF}.`,
      inputSchema: z.object({
        name: z.string().describe('Trigger name to delete.'),
        expected_name: z
          .string()
          .describe('Must exactly match name as a deletion safeguard.'),
      }),
    },
    async ({ name, expected_name }) => {
      deleteGuard(name, expected_name, 'name');
      await client.delete(`${ROUTE}/${encodePathSegment(name)}`);
      return text(JSON.stringify({ deleted: true, name, kind: 'trigger' }));
    },
  );
}

// ---------------------------------------------------------------------------
// test_trigger (PATCH dry-run)
// ---------------------------------------------------------------------------

function registerTestTrigger(server: McpServer, client: StreamClient): void {
  registerTool(
    server,
    'test_trigger',
    {
      description:
        'Dry-run a trigger without persisting it. EMAIL test only renders the ' +
        'template (never sends mail). REST test performs a REAL outbound HTTP ' +
        'call to url and returns the remote response (status, headers, body); ' +
        'credential-bearing headers and reflected request/response bodies are ' +
        'redacted before they reach you. Optional dictionary supplies {{var}} ' +
        'template bindings. EXTERNAL_RL_STORAGE is not supported.' +
        `\n\nRef: ${KNOWLEDGE_REF}.`,
      // REST test makes Stream perform a REAL outbound HTTP call to a
      // caller-supplied URL -> genuinely open-world (unlike the closed
      // Stream-API default).
      annotations: { openWorldHint: true },
      inputSchema: z.object({
        trigger: triggerInputSchema.describe(
          'Full EMAIL or REST trigger object to test (validated like create).',
        ),
        dictionary: z
          .array(
            z.object({
              key: z.string(),
              value: z.string(),
            }),
          )
          .optional()
          .describe(
            'Template variable bindings ({key,value}[]) used to render ' +
              'title/body/url/payload/headers.',
          ),
      }),
    },
    async ({ trigger, dictionary }) => {
      validateTrigger(trigger);
      const body: Record<string, unknown> = {
        trigger: buildTriggerPayload(trigger),
      };
      if (dictionary !== undefined) body['dictionary'] = dictionary;
      const result = await client.patch<Record<string, unknown>>(ROUTE, body);
      return text(JSON.stringify(scrubTestResult(result)));
    },
  );
}
