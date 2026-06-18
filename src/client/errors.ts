const SENSITIVE_FIELDS = new Set([
  'apiKey',
  'apiSecret',
  'password',
  'secret',
  'privateKey',
  'clientSecret',
  'token',
  'passphrase',
  'credential',
  // Stream write-only secret holders: the `{clear, secure}` secret object's
  // clear field, and the PKCS#11 pin. Reference NAMES (keystore, credentials,
  // proxy) stay visible — they are not secrets.
  'pin',
  'clear',
  // `secure` is the encrypted/secured half of Stream's `{clear, secure}` secret
  // object. Redact it alongside `clear` so neither half of a PIN / password /
  // private key can leak through an error body or a create/update echo.
  'secure',
  'secretKey',
  'accessKey',
  'pkcs12',
]);

// Specific Stream error codes -> remediation hints.
const SPECIFIC_REMEDIATION: Record<string, string> = {
  'STREAMQL-001':
    'Invalid query syntax. An empty query is not allowed - use `id exists` to ' +
    'match all, or a valid filter expression.',
  'SEC-AUTH-002':
    'Authentication failed. Check credentials - STREAM_API_ID/STREAM_API_KEY ' +
    'for local-account auth (and STREAM_API_IDPROV, default "local"), or the ' +
    'client certificate for mTLS.',
  'SEC-AUTH-007':
    'Invalid identity provider. Set STREAM_API_IDPROV to a valid enabled ' +
    'provider name (the local provider is usually "local").',
  'SEC-PERM-001':
    'Insufficient permissions. The authenticated principal lacks the required ' +
    'role/permission for this operation.',
};

// Error code suffix -> remediation hint (Stream uses <DOMAIN>-NNN codes).
const SUFFIX_REMEDIATION: Record<string, string> = {
  '003': 'Not found. Use the corresponding list_* tool to see available items.',
  '004': 'Already exists. Use the corresponding update_* tool instead.',
  '005': 'Referenced by other objects. Remove references first, then retry.',
  '002':
    'Validation failed. Check the error details for specific field issues.',
};

export class StreamError extends Error {
  readonly statusCode: number;
  readonly errorCode: string | undefined;
  readonly detail: string | undefined;
  readonly remediation: string | undefined;

  constructor(
    statusCode: number,
    opts: {
      errorCode?: string;
      message?: string;
      detail?: string;
      remediation?: string;
    } = {},
  ) {
    super(
      StreamError._format(
        statusCode,
        opts.errorCode,
        opts.message,
        opts.detail,
        opts.remediation,
      ),
    );
    this.name = 'StreamError';
    this.statusCode = statusCode;
    this.errorCode = opts.errorCode;
    this.detail = opts.detail;
    this.remediation = opts.remediation;
  }

  toToolResult(): string {
    return this.message;
  }

  private static _format(
    statusCode: number,
    errorCode?: string,
    message?: string,
    detail?: string,
    remediation?: string,
  ): string {
    const parts: string[] = [];
    let header = `Stream API error ${statusCode}`;
    if (errorCode) header += ` [${errorCode}]`;
    parts.push(header);
    if (message) parts.push(message);
    if (detail) parts.push(`Detail: ${detail}`);
    if (remediation) parts.push(`Hint: ${remediation}`);
    return parts.join('. ');
  }
}

export function redactSensitive(data: unknown): unknown {
  if (data === null || data === undefined) return data;
  if (Array.isArray(data)) return data.map(redactSensitive);
  if (typeof data === 'object') {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(data as Record<string, unknown>)) {
      result[k] = SENSITIVE_FIELDS.has(k) ? '<redacted>' : redactSensitive(v);
    }
    return result;
  }
  return data;
}

// Anything matching these patterns inside an error message is a leak risk.
const PEM_PRIVATE_KEY_RE =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;
const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
const LONG_BASE64_RE = /[A-Za-z0-9+/=_-]{40,}/g;

const MAX_ERROR_FIELD_LENGTH = 200;

/**
 * Scrub PEM private keys, JWT tokens, and long base64-ish blobs from a
 * free-form string, then truncate to MAX_ERROR_FIELD_LENGTH chars.
 */
export function redactValue(s: string): string {
  if (!s) return s;
  let scrubbed = s
    .replace(PEM_PRIVATE_KEY_RE, '<redacted-private-key>')
    .replace(JWT_RE, '<redacted-jwt>')
    // Long base64-ish run -> likely a key/secret blob. But a pure-hex run of a
    // bounded length is almost always an identifier (thumbprint, serial,
    // request id), not a secret, so keep it readable - redacting it just turns
    // a useful "thumbprint mismatch" error into noise. Real base64 secrets
    // contain non-hex characters (g-z, +, /, =).
    .replace(LONG_BASE64_RE, (m) =>
      /^[0-9a-fA-F]+$/.test(m) && m.length <= 128 ? m : '<redacted-blob>',
    );
  if (scrubbed.length > MAX_ERROR_FIELD_LENGTH) {
    scrubbed = scrubbed.slice(0, MAX_ERROR_FIELD_LENGTH) + '... [truncated]';
  }
  return scrubbed;
}

function resolveRemediation(errorCode: string | undefined): string | undefined {
  if (!errorCode) return undefined;
  if (errorCode in SPECIFIC_REMEDIATION) return SPECIFIC_REMEDIATION[errorCode];
  // The numeric-suffix fallback (002=validation, 003=not-found, 004=exists,
  // 005=referenced) only holds for the CRUD-style config domains. Security/auth
  // codes (SEC-AUTH-003 "no such identity", SEC-PERM-004, ...) reuse the same
  // suffixes with different meanings, so a generic hint there is actively
  // misleading - prefer no hint over a wrong one.
  if (/^SEC[-A-Z]/.test(errorCode)) return undefined;
  const suffix = errorCode.includes('-') ? errorCode.split('-').pop()! : '';
  return SUFFIX_REMEDIATION[suffix];
}

/**
 * Parse a Stream error response body into a StreamError.
 * Stream error shape: `{ "error": "CA-003", "message": "...", "title": "...",
 * "detail": "...", "status": 404 }`. Falls back gracefully for nested or
 * non-JSON bodies.
 */
export function parseErrorResponse(
  statusCode: number,
  body: string,
): StreamError {
  let parsed: unknown;
  try {
    parsed = body ? JSON.parse(body) : {};
  } catch {
    return new StreamError(statusCode, {
      message: body ? redactValue(body) : `HTTP ${statusCode}`,
    });
  }

  // Valid JSON, but not the `{ error, message, ... }` object shape Stream uses
  // (e.g. a bare array of validation strings, or a quoted string from a proxy).
  // Surface the scrubbed body verbatim rather than mis-reading fields off it.
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return new StreamError(statusCode, {
      message: body ? redactValue(body) : `HTTP ${statusCode}`,
    });
  }

  const raw = redactSensitive(parsed) as Record<string, unknown>;

  let errorCode: string | undefined;
  let message: string | undefined;
  let detail: string | undefined;

  const rawError = raw['error'];
  if (typeof rawError === 'object' && rawError !== null) {
    // Defensive: some endpoints nest `{ error: { code/message/detail } }`.
    const errObj = rawError as Record<string, unknown>;
    errorCode =
      (errObj['code'] as string | undefined) ??
      (errObj['error'] as string | undefined);
    message =
      (errObj['message'] as string | undefined) ??
      (raw['message'] as string | undefined) ??
      (raw['title'] as string | undefined) ??
      '';
    detail =
      (errObj['detail'] as string | undefined) ??
      (raw['detail'] as string | undefined);
  } else {
    // Standard Stream shape: top-level string `error` code.
    errorCode =
      (rawError as string | undefined) ?? (raw['code'] as string | undefined);
    message =
      (raw['message'] as string | undefined) ??
      (raw['title'] as string | undefined) ??
      '';
    detail = raw['detail'] as string | undefined;
  }

  if (errorCode !== undefined && typeof errorCode !== 'string') {
    errorCode = String(errorCode);
  }

  return new StreamError(statusCode, {
    errorCode,
    message: message ? redactValue(message) : message,
    detail: detail ? redactValue(detail) : detail,
    remediation: resolveRemediation(errorCode),
  });
}

/**
 * Raised when an HTTP response body does not match a caller-provided Zod
 * schema. The diff is truncated to keep error messages bounded.
 */
export class StreamResponseValidationError extends StreamError {
  readonly issues: string;

  constructor(opts: { path: string; statusCode: number; issues: string }) {
    const truncatedIssues =
      opts.issues.length > 500
        ? opts.issues.slice(0, 500) + '... [truncated]'
        : opts.issues;
    super(opts.statusCode, {
      errorCode: 'RESPONSE_VALIDATION_FAILED',
      message: `Response from ${opts.path} did not match expected schema`,
      detail: truncatedIssues,
      remediation:
        'Check the Stream version compatibility or update the response schema ' +
        'used by this tool.',
    });
    this.name = 'StreamResponseValidationError';
    this.issues = truncatedIssues;
  }
}
