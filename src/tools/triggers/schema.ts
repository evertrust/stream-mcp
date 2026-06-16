/**
 * Zod input schema + wire-payload builder for EMAIL and REST triggers.
 *
 * The trigger object is polymorphic on `type`. The input is modeled as a single
 * flat z.object (so the MCP SDK publishes a usable JSON Schema with all fields —
 * a top-level z.discriminatedUnion would normalize to an empty object schema and
 * hide every field from the model). Per-type required fields and the documented
 * invariants are enforced in validateTrigger(), which throws a StreamError the
 * model can self-correct from.
 *
 * Inputs are snake_case; the builder maps to the EXACT camelCase wire field
 * names from docs/audit/triggers.md.
 */
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import {
  NOTIFICATION_TYPES,
  REST_AUTH_TYPES,
  REST_METHODS,
  REST_PAYLOAD_TYPES,
  RUN_PERIOD_EVENTS,
  TRIGGER_EVENTS,
} from './enums.js';

// ---------------------------------------------------------------------------
// Nested schemas
// ---------------------------------------------------------------------------

const headerSchema = z.object({
  name: z.string().describe('Header name.'),
  value: z
    .string()
    .describe('Header value (TemplateString; supports {{var}} placeholders).'),
});

export const emailTemplateSchema = z.object({
  to: z
    .array(z.string())
    .optional()
    .describe('Recipient addresses (verbatim, not templated).'),
  from: z.string().describe('Sender address.'),
  title: z.string().describe('Subject (TemplateString; {{var}} placeholders).'),
  body: z
    .string()
    .optional()
    .describe('Body (TemplateString; {{var}} placeholders).'),
  is_html: z.boolean().describe('true -> HTML body, false -> plain text.'),
});

// ---------------------------------------------------------------------------
// Flat polymorphic input schema (type-conditional fields validated below)
// ---------------------------------------------------------------------------

export const triggerInputSchema = z.object({
  type: z
    .enum(NOTIFICATION_TYPES)
    .describe(
      'Discriminator: email | rest. (EXTERNAL_RL_STORAGE is managed by the ' +
        'RL-storage tools.)',
    ),
  name: z
    .string()
    .regex(
      /^[0-9a-zA-Z\-_.]+$/,
      'name must match [0-9a-zA-Z-_.]+ (letters, digits, - _ . ; no spaces).',
    )
    .describe('Trigger name (immutable primary key; no spaces).'),
  event: z
    .enum(TRIGGER_EVENTS)
    .describe(
      'Trigger event. Determines runPeriod rules: expiration events ' +
        '(on_*_expiration) REQUIRE run_period; all other events FORBID it.',
    ),
  run_period: z
    .string()
    .optional()
    .describe(
      'Duration like "5 days" / "30 seconds" (units: ms/s/m/h/d). REQUIRED for ' +
        'expiration events, FORBIDDEN for all other events.',
    ),
  on_trigger_error: z
    .array(z.string())
    .optional()
    .describe(
      'Names of OTHER existing triggers (runnable on on_trigger_error) fired if ' +
        'this trigger errors. Forbidden when this event is on_trigger_error.',
    ),
  // -- EMAIL fields --
  template: emailTemplateSchema
    .optional()
    .describe('EMAIL only — required for type=email.'),
  // -- REST fields --
  authentication_type: z
    .enum(REST_AUTH_TYPES)
    .optional()
    .describe(
      'REST only (required for type=rest). basic->Password creds, bearer->Raw ' +
        'creds, custom->Password|Raw creds, x509->X509 creds, noauth->no creds.',
    ),
  credentials: z
    .string()
    .optional()
    .describe(
      'REST only — name of existing rest-target credentials. Required by ' +
        'basic/bearer/custom/x509; MUST be omitted for noauth.',
    ),
  proxy: z
    .string()
    .optional()
    .describe('REST only — name of an existing HTTP proxy.'),
  method: z
    .enum(REST_METHODS)
    .optional()
    .describe('REST only (required for type=rest). HTTP method (uppercase).'),
  url: z
    .string()
    .optional()
    .describe(
      'REST only (required for type=rest). Endpoint URL (TemplateString).',
    ),
  payload: z
    .string()
    .optional()
    .describe('REST only — request body (TemplateString; {{var}}).'),
  payload_type: z
    .enum(REST_PAYLOAD_TYPES)
    .optional()
    .describe('REST only — json or text.'),
  timeout: z
    .string()
    .optional()
    .describe(
      'REST only — request timeout duration (default "5 seconds"; must be > 0).',
    ),
  headers: z
    .array(headerSchema)
    .optional()
    .describe('REST only — request headers.'),
  expected_http_codes: z
    .array(z.number().int())
    .optional()
    .describe(
      'REST only (required for type=rest). Non-empty list of HTTP codes ' +
        'treated as success.',
    ),
});

export type TriggerInput = z.infer<typeof triggerInputSchema>;

// ---------------------------------------------------------------------------
// Wire payload builder (snake_case -> camelCase)
// ---------------------------------------------------------------------------

export function buildTriggerPayload(
  args: TriggerInput,
): Record<string, unknown> {
  return args.type === 'email'
    ? buildEmailPayload(args)
    : buildRestPayload(args);
}

function buildTriggersBlock(
  onTriggerError: string[] | undefined,
): Record<string, unknown> | undefined {
  if (onTriggerError === undefined) return undefined;
  return { onTriggerError };
}

function buildEmailPayload(args: TriggerInput): Record<string, unknown> {
  const template = args.template!;
  const payload: Record<string, unknown> = {
    type: 'email',
    name: args.name,
    event: args.event,
    template: {
      from: template.from,
      title: template.title,
      isHtml: template.is_html,
      ...(template.to !== undefined ? { to: template.to } : {}),
      ...(template.body !== undefined ? { body: template.body } : {}),
    },
  };
  if (args.run_period !== undefined) payload['runPeriod'] = args.run_period;
  const triggers = buildTriggersBlock(args.on_trigger_error);
  if (triggers !== undefined) payload['triggers'] = triggers;
  return payload;
}

function buildRestPayload(args: TriggerInput): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    type: 'rest',
    name: args.name,
    event: args.event,
    authenticationType: args.authentication_type,
    method: args.method,
    url: args.url,
    expectedHttpCodes: args.expected_http_codes,
  };
  if (args.run_period !== undefined) payload['runPeriod'] = args.run_period;
  if (args.credentials !== undefined) payload['credentials'] = args.credentials;
  if (args.proxy !== undefined) payload['proxy'] = args.proxy;
  if (args.payload !== undefined) payload['payload'] = args.payload;
  if (args.payload_type !== undefined)
    payload['payloadType'] = args.payload_type;
  if (args.timeout !== undefined) payload['timeout'] = args.timeout;
  if (args.headers !== undefined) payload['headers'] = args.headers;
  const triggers = buildTriggersBlock(args.on_trigger_error);
  if (triggers !== undefined) payload['triggers'] = triggers;
  return payload;
}

// ---------------------------------------------------------------------------
// Cross-field validation (client-side; throws StreamError for self-correction)
// ---------------------------------------------------------------------------

/**
 * Enforce the trigger invariants documented in the audit before any HTTP call:
 *   - type ∈ {email, rest} (external_rl_storage routed elsewhere)
 *   - per-type required fields (email: template; rest: authentication_type,
 *     method, url, expected_http_codes)
 *   - runPeriod required for expiration events, forbidden otherwise
 *   - on_trigger_error forbidden when the trigger's own event is on_trigger_error
 *   - REST: expectedHttpCodes non-empty; noauth forbids credentials; other auth
 *     types require credentials
 */
export function validateTrigger(args: TriggerInput): void {
  if (!(NOTIFICATION_TYPES as readonly string[]).includes(args.type)) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-TYPE-UNSUPPORTED',
      message: `Unsupported trigger type "${args.type}". Use email or rest.`,
      remediation:
        'EXTERNAL_RL_STORAGE triggers are managed by the RL-storage tools.',
    });
  }

  const requiresRunPeriod = RUN_PERIOD_EVENTS.has(args.event);
  if (requiresRunPeriod && args.run_period === undefined) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-RUNPERIOD-REQUIRED',
      message: `run_period is mandatory for expiration event "${args.event}".`,
      remediation: 'Provide run_period like "5 days" / "30 seconds".',
    });
  }
  if (!requiresRunPeriod && args.run_period !== undefined) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-RUNPERIOD-FORBIDDEN',
      message: `run_period is forbidden for non-expiration event "${args.event}".`,
      remediation: 'Omit run_period for this event.',
    });
  }

  if (
    args.event === 'on_trigger_error' &&
    args.on_trigger_error !== undefined
  ) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-ONERROR-FORBIDDEN',
      message:
        'on_trigger_error must not be set when the trigger event is on_trigger_error.',
      remediation: 'Omit on_trigger_error for on_trigger_error triggers.',
    });
  }

  if (args.type === 'email') {
    if (args.template === undefined) {
      throw new StreamError(422, {
        errorCode: 'TRIGGER-TEMPLATE-REQUIRED',
        message: 'template is required for type=email.',
        remediation: 'Provide template with from, title, is_html.',
      });
    }
    return;
  }

  // type === 'rest'
  const missing = ([] as string[]).concat(
    args.authentication_type === undefined ? ['authentication_type'] : [],
    args.method === undefined ? ['method'] : [],
    args.url === undefined ? ['url'] : [],
    args.expected_http_codes === undefined ? ['expected_http_codes'] : [],
  );
  if (missing.length > 0) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-REST-MISSING',
      message: `Missing required REST field(s): ${missing.join(', ')}.`,
      remediation:
        'Provide authentication_type, method, url, expected_http_codes.',
    });
  }
  if (args.expected_http_codes!.length === 0) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-HTTPCODES-EMPTY',
      message: 'expected_http_codes must contain at least one HTTP code.',
    });
  }
  if (args.authentication_type === 'noauth') {
    if (args.credentials !== undefined) {
      throw new StreamError(422, {
        errorCode: 'TRIGGER-NOAUTH-CREDS',
        message:
          'credentials must not be specified when authentication_type=noauth.',
        remediation:
          'Remove credentials, or pick a non-noauth authentication_type.',
      });
    }
  } else if (args.credentials === undefined) {
    throw new StreamError(422, {
      errorCode: 'TRIGGER-CREDS-REQUIRED',
      message: `credentials is required for authentication_type=${args.authentication_type}.`,
      remediation:
        'basic->Password, bearer->Raw, custom->Password|Raw, x509->X509 credentials.',
    });
  }
}
