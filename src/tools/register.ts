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

import { StreamError } from '../client/errors.js';
import { buildToolDescription } from './guidance.js';

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

function titleFromName(name: string): string {
  const override = TITLE_OVERRIDES[name];
  if (override) return override;
  return name
    .split('_')
    .map((seg) =>
      seg.length === 0 ? seg : seg[0]!.toUpperCase() + seg.slice(1),
    )
    .join(' ');
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

function wrapHandler(
  handler: (...args: unknown[]) => ToolResult,
): (...args: unknown[]) => Promise<CallToolResult> {
  return async (...args: unknown[]) => {
    try {
      return await handler(...args);
    } catch (err) {
      if (err instanceof StreamError) return streamErrorToToolResult(err);
      throw err;
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

  const description = wrapDescription
    ? buildToolDescription(name, config.description)
    : config.description;

  const annotations: ToolAnnotations = {
    ...classification.annotations,
    ...config.annotations,
  };
  const title = config.title ?? classification.title;

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
