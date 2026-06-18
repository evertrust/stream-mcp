import type {
  McpServer,
  ToolCallback,
} from '@modelcontextprotocol/sdk/server/mcp.js';
import type {
  AnySchema,
  ZodRawShapeCompat,
} from '@modelcontextprotocol/sdk/server/zod-compat.js';
import type { RequestHandlerExtra } from '@modelcontextprotocol/sdk/shared/protocol.js';
import type {
  CallToolResult,
  ServerNotification,
  ServerRequest,
  ToolAnnotations,
} from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';

import { StreamError, redactValue } from '../client/errors.js';
import { getLogger } from '../logging.js';
import { buildToolDescription } from './guidance.js';

const logger = getLogger('stream_mcp.tools');

type ToolExtra = RequestHandlerExtra<ServerRequest, ServerNotification>;

type ToolConfigBase = {
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: ToolAnnotations;
  _meta?: Record<string, unknown>;
};

type ToolResult = CallToolResult | Promise<CallToolResult>;

export interface RegisterToolOptions {
  readonly wrapDescription?: boolean;
  readonly wrapErrors?: boolean;
}

// ---------------------------------------------------------------------------
// Name-prefix classification
// ---------------------------------------------------------------------------
//
// readOnlyHint    -> true for queries and non-mutating generators (CSR, decode).
// destructiveHint -> true for delete/remove/revoke.
// idempotentHint  -> true for updates/upserts/assign/reset/migrate that converge.
// openWorldHint   -> true for anything that mutates or reaches Stream's network.

interface Classification {
  readonly annotations: ToolAnnotations;
  readonly title: string;
}

const TITLE_OVERRIDES: Record<string, string> = {
  whoami: 'Who am I',
  get_license_info: 'License info',
  get_license_modules: 'License modules',
  generate_ca_csr: 'Generate CA CSR',
  generate_ocsp_signer_csr: 'Generate OCSP signer CSR',
  generate_tsa_signer_csr: 'Generate TSA signer CSR',
  decode_x509: 'Decode X.509 certificate',
  decode_csr: 'Decode CSR',
  decode_crl: 'Decode CRL',
  decode_openssh_pubkey: 'Decode OpenSSH public key',
  detect_file: 'Detect file format',
  extract_pkcs12: 'Extract PKCS#12',
  export_configuration: 'Export configuration (AsciiDoc)',
};

// PKI acronyms that should render upper-case (with the natural plural) rather
// than title-cased, e.g. "List CAs" not "List Cas", "Get OCSP signer".
const ACRONYM_SEGMENTS: Record<string, string> = {
  ca: 'CA',
  cas: 'CAs',
  crl: 'CRL',
  crls: 'CRLs',
  csr: 'CSR',
  ocsp: 'OCSP',
  tsa: 'TSA',
  ssh: 'SSH',
  krl: 'KRL',
  krls: 'KRLs',
  hsm: 'HSM',
  ntp: 'NTP',
  eku: 'EKU',
  ekus: 'EKUs',
  dn: 'DN',
  san: 'SAN',
  aia: 'AIA',
  tls: 'TLS',
};

function capitalizeSegment(seg: string): string {
  if (seg.length === 0) return seg;
  return ACRONYM_SEGMENTS[seg] ?? seg[0]!.toUpperCase() + seg.slice(1);
}

function titleFromName(name: string): string {
  const override = TITLE_OVERRIDES[name];
  if (override) return override;
  return name.split('_').map(capitalizeSegment).join(' ');
}

// Read-only verbs / patterns: queries + non-mutating generators.
// `find_` covers read-only POST searches (e.g. find_ca_keys).
const READ_ONLY_RE =
  /^(list|get|search|find|aggregate|describe|decode|detect|export|extract)_/;

function classify(name: string): Classification {
  const title = titleFromName(name);

  const isReadOnly =
    READ_ONLY_RE.test(name) || name === 'whoami' || name.endsWith('_csr'); // generate_*_csr: derives a CSR, no state change
  // NB: run_event_integrity_check is intentionally NOT read-only — it kicks off
  // a background verification and persists an append-only integrity report, so
  // it falls through to the additive (non-idempotent, open-world) branch.

  if (isReadOnly) {
    return {
      annotations: {
        title,
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      title,
    };
  }

  // Destructive mutations
  if (/^(delete|remove)_/.test(name) || /^revoke_/.test(name)) {
    return {
      annotations: {
        title,
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
      title,
    };
  }

  // Idempotent mutations (converge to the same state).
  // NB: migrate_* is one-way (repeat -> CA-009) and reset_* mints fresh state
  // (new password) each call, so neither is idempotent - they fall through to
  // the additive branch below.
  if (/^(update|set|upsert|assign)_/.test(name)) {
    return {
      annotations: {
        title,
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
      title,
    };
  }

  // Additive / other mutations (create/add/issue/enroll/enhance/upload/test/...)
  return {
    annotations: {
      title,
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    title,
  };
}

/** Human-readable safety-tier label, matching the scaffold's vocabulary. */
function tierLabel(a: ToolAnnotations): string {
  if (a.readOnlyHint) return 'read-only';
  if (a.destructiveHint) return 'mutating-destructive';
  return 'mutating-safe';
}

// ---------------------------------------------------------------------------
// isError wrapping
// ---------------------------------------------------------------------------

function streamErrorToToolResult(err: StreamError): CallToolResult {
  const structured: Record<string, unknown> = {
    errorCode: err.errorCode ?? null,
    statusCode: err.statusCode,
    message: err.message,
  };
  if (err.detail !== undefined) structured['detail'] = err.detail;
  if (err.remediation !== undefined)
    structured['remediation'] = err.remediation;

  return {
    isError: true,
    content: [{ type: 'text', text: err.toToolResult() }],
    structuredContent: structured,
  };
}

function unexpectedErrorToToolResult(err: unknown): CallToolResult {
  // Log the full detail server-side (stderr only - never in a tool result),
  // then return a redacted, bounded message so a stack trace or any secret a
  // bug surfaced cannot leak into the model context.
  const full = err instanceof Error ? (err.stack ?? err.message) : String(err);
  logger.error(`Unhandled tool error: ${full}`);
  const message = redactValue(err instanceof Error ? err.message : String(err));
  return {
    isError: true,
    content: [{ type: 'text', text: `Internal error: ${message}` }],
    structuredContent: { errorCode: 'INTERNAL_ERROR', message },
  };
}

function wrapHandler(
  handler: (...args: unknown[]) => ToolResult,
): (...args: unknown[]) => Promise<CallToolResult> {
  return async (...args: unknown[]) => {
    try {
      return await handler(...args);
    } catch (err) {
      if (err instanceof StreamError) return streamErrorToToolResult(err);
      return unexpectedErrorToToolResult(err);
    }
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function registerTool(
  server: McpServer,
  name: string,
  config: ToolConfigBase & { inputSchema?: undefined },
  cb: (extra: ToolExtra) => ToolResult,
  options?: RegisterToolOptions,
): ReturnType<McpServer['registerTool']>;

export function registerTool<InputSchema extends z.ZodTypeAny>(
  server: McpServer,
  name: string,
  config: ToolConfigBase & { inputSchema: InputSchema },
  cb: (args: z.infer<InputSchema>, extra: ToolExtra) => ToolResult,
  options?: RegisterToolOptions,
): ReturnType<McpServer['registerTool']>;

export function registerTool(
  server: McpServer,
  name: string,
  config: ToolConfigBase,
  cb:
    | ((args: unknown, extra: ToolExtra) => ToolResult)
    | ((extra: ToolExtra) => ToolResult),
  options: RegisterToolOptions = {},
) {
  const wrapDescription = options.wrapDescription ?? true;
  const wrapErrors = options.wrapErrors ?? true;
  const classification = classify(name);

  const description0 = wrapDescription
    ? buildToolDescription(name, config.description)
    : config.description;

  const annotations: ToolAnnotations = {
    ...classification.annotations,
    ...config.annotations,
  };
  const title = config.title ?? classification.title;

  // Ensure every tool description ends with a human-readable "Safety tier" line,
  // derived from the (final, possibly-overridden) annotations. Most tools write
  // it by hand; this backstops the ~17 hand-written query/lifecycle tools that
  // omit it, so the vocabulary the server instructions teach is always present.
  const description =
    wrapDescription &&
    typeof description0 === 'string' &&
    !description0.includes('Safety tier')
      ? `${description0.trimEnd()}\nSafety tier: ${tierLabel(annotations)}`
      : description0;

  const handler = wrapErrors
    ? wrapHandler(cb as (...args: unknown[]) => ToolResult)
    : (cb as (...args: unknown[]) => Promise<CallToolResult>);

  const sdkConfig: Record<string, unknown> = {
    ...config,
    title,
    description,
    annotations,
    inputSchema:
      config.inputSchema === undefined
        ? undefined
        : (config.inputSchema as unknown as AnySchema | ZodRawShapeCompat),
  };

  return server.registerTool(
    name,
    sdkConfig as never,
    handler as unknown as ToolCallback<AnySchema | ZodRawShapeCompat>,
  );
}
