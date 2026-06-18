import { randomUUID } from 'node:crypto';
import {
  Agent,
  FormData as UndiciFormData,
  fetch as undiciFetch,
} from 'undici';
import type { RequestInit as UndiciRequestInit } from 'undici';
import type { ZodType } from 'zod';

import type { AuthProvider } from '../auth/base.js';
import { getLogger } from '../logging.js';
import {
  StreamError,
  StreamResponseValidationError,
  parseErrorResponse,
} from './errors.js';
import { withRetry } from './retry.js';

const logger = getLogger('stream_mcp.client');

// Defense-in-depth cap on response bodies the client will parse.
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

// Connection-error cause codes we know how to classify.
const CONNECTION_CAUSE_CODES = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'ETIMEDOUT',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'ECONNABORTED',
  'EAI_AGAIN',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

// TLS-handshake failure codes get a TLS-specific remediation (often a verifySsl
// or trust-store issue rather than a connectivity one).
const TLS_CAUSE_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED',
]);

function getCauseCode(err: unknown): string | undefined {
  if (err && typeof err === 'object' && 'cause' in err) {
    const cause = (err as { cause?: unknown }).cause;
    if (cause && typeof cause === 'object' && 'code' in cause) {
      return (cause as { code?: string }).code;
    }
  }
  return undefined;
}

function getErrorName(err: unknown): string | undefined {
  if (err && typeof err === 'object' && 'name' in err) {
    return (err as { name?: string }).name;
  }
  return undefined;
}

function oversizedError(path: string, bytes: number): StreamError {
  return new StreamError(0, {
    message: `Response from ${path} exceeds ${MAX_RESPONSE_BYTES} bytes (${bytes})`,
    remediation:
      'Use a paginated endpoint or narrow the request to reduce payload size.',
  });
}

/** Reject before reading the body if Content-Length already exceeds the cap. */
function assertDeclaredSizeWithinCap(resp: Response, path: string): void {
  const contentLength = resp.headers.get('content-length');
  if (!contentLength) return;
  const declared = Number.parseInt(contentLength, 10);
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw oversizedError(path, declared);
  }
}

/** Bound JSON.parse to MAX_RESPONSE_BYTES. */
async function readJsonBounded<T>(resp: Response, path: string): Promise<T> {
  const contentLength = resp.headers.get('content-length');
  if (contentLength) {
    const declared = Number.parseInt(contentLength, 10);
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      throw new StreamError(0, {
        message: `Response from ${path} exceeds ${MAX_RESPONSE_BYTES} bytes (Content-Length: ${declared})`,
        remediation:
          'Use a paginated endpoint or narrow the query to reduce payload size.',
      });
    }
  }
  const text = await resp.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    throw new StreamError(0, {
      message: `Response from ${path} exceeds ${MAX_RESPONSE_BYTES} bytes (received: ${text.length})`,
      remediation:
        'Use a paginated endpoint or narrow the query to reduce payload size.',
    });
  }
  if (!text) return null as unknown as T;
  return JSON.parse(text) as T;
}

/**
 * Read an HTTP error body without buffering an unbounded payload: if the
 * declared size already exceeds the cap, skip the read; otherwise read and
 * truncate. Error bodies are tiny in practice, but a misbehaving proxy can
 * return a huge HTML page on a 5xx.
 */
async function readErrorBodyBounded(resp: Response): Promise<string> {
  const contentLength = resp.headers.get('content-length');
  if (contentLength) {
    const declared = Number.parseInt(contentLength, 10);
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      return `<error body omitted: ${declared} bytes exceeds ${MAX_RESPONSE_BYTES}>`;
    }
  }
  const text = await resp.text();
  return Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES
    ? text.slice(0, MAX_RESPONSE_BYTES)
    : text;
}

export interface RequestOptions<T = unknown> {
  timeout?: number;
  schema?: ZodType<T>;
  /**
   * Opt out of automatic retry for a safe (GET/HEAD) request that nonetheless
   * has a side effect server-side (e.g. generate_crl/generate_krl trigger
   * asynchronous generation via GET). Retrying those would re-fire the action.
   */
  noRetry?: boolean;
}

export interface MultipartPart {
  fieldName: string;
  filename: string;
  mimeType: string;
  data: Buffer | string;
}

export class StreamClient {
  private readonly _baseUrl: string;
  private readonly _auth: AuthProvider;
  private readonly _timeout: number;
  readonly exportTimeout: number;
  private readonly _agent: Agent;
  private readonly _testedVersions: readonly string[];
  private readonly _warnVersions: readonly string[];
  private _initialized = false;
  private _initPromise: Promise<void> | null = null;

  // Captured during lazy init.
  principalName: string | undefined;
  streamVersion: string | undefined;

  constructor(
    baseUrl: string,
    auth: AuthProvider,
    options: {
      timeout: number;
      exportTimeout: number;
      verifySsl: boolean;
      testedVersions?: readonly string[];
      warnVersions?: readonly string[];
    },
  ) {
    this._baseUrl = baseUrl.replace(/\/+$/, '');
    this._auth = auth;
    this._timeout = options.timeout * 1000;
    this.exportTimeout = options.exportTimeout * 1000;
    this._testedVersions = options.testedVersions ?? [];
    this._warnVersions = options.warnVersions ?? [];

    if (!options.verifySsl) {
      logger.warning(
        'TLS certificate verification is DISABLED (STREAM_VERIFY_SSL=false) - ' +
          'the connection to Stream is vulnerable to interception. Never use ' +
          'this in production.',
      );
    }

    const authConnect = auth.getDispatcherOptions();
    const connectOptions: Agent.Options['connect'] = {
      ...((typeof authConnect === 'object' ? authConnect : {}) as Record<
        string,
        unknown
      >),
      rejectUnauthorized: options.verifySsl,
    };
    this._agent = new Agent({ connect: connectOptions });
  }

  // -- Public API -----------------------------------------------------------

  /** GET a single resource. Returns parsed JSON, or null on 204. */
  async get<T = unknown>(
    path: string,
    params?: URLSearchParams,
    opts?: RequestOptions<T>,
  ): Promise<T> {
    const url = params ? `${path}?${params.toString()}` : path;
    const resp = await this._request('GET', url, {
      timeoutMs: opts?.timeout ? opts.timeout * 1000 : undefined,
      noRetry: opts?.noRetry,
    });
    if (resp.status === 204) return null as unknown as T;
    const parsed = await readJsonBounded<T>(resp, url);
    return opts?.schema
      ? (this._validateOrThrow(opts.schema, parsed, url, resp.status) as T)
      : parsed;
  }

  /**
   * GET a collection. Stream returns HTTP 204 for empty collections (and when
   * the caller lacks AUDIT permission) - both map to an empty array here.
   * Accepts a bare array, or an `{ items: [...] }` / `{ results: [...] }`
   * envelope.
   */
  async getList<T = unknown>(
    path: string,
    params?: URLSearchParams,
  ): Promise<T[]> {
    const url = params ? `${path}?${params.toString()}` : path;
    const resp = await this._request('GET', url, {});
    if (resp.status === 204) return [];
    const parsed = await readJsonBounded<unknown>(resp, url);
    if (Array.isArray(parsed)) return parsed as T[];
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      if (Array.isArray(obj['items'])) return obj['items'] as T[];
      if (Array.isArray(obj['results'])) return obj['results'] as T[];
    }
    return parsed == null ? [] : [parsed as T];
  }

  async post<T = unknown>(
    path: string,
    body?: unknown,
    opts?: RequestOptions<T>,
  ): Promise<T> {
    return this._requestJson<T>(
      'POST',
      path,
      {
        body: body !== undefined ? JSON.stringify(body) : undefined,
        timeoutMs: opts?.timeout ? opts.timeout * 1000 : undefined,
      },
      opts,
    );
  }

  async put<T = unknown>(
    path: string,
    body: unknown,
    opts?: RequestOptions<T>,
  ): Promise<T> {
    return this._requestJson<T>(
      'PUT',
      path,
      { body: JSON.stringify(body) },
      opts,
    );
  }

  async patch<T = unknown>(
    path: string,
    body: unknown,
    opts?: RequestOptions<T>,
  ): Promise<T> {
    return this._requestJson<T>(
      'PATCH',
      path,
      { body: JSON.stringify(body) },
      opts,
    );
  }

  async delete(path: string): Promise<unknown | null> {
    const resp = await this._request('DELETE', path, {});
    if (resp.status === 204) return null;
    return readJsonBounded<unknown>(resp, path);
  }

  /** DELETE with a JSON request body (e.g. role/team member removal). */
  async deleteWithBody(path: string, body: unknown): Promise<unknown | null> {
    const resp = await this._request('DELETE', path, {
      body: JSON.stringify(body),
    });
    if (resp.status === 204) return null;
    return readJsonBounded<unknown>(resp, path);
  }

  async getBytes(path: string, timeoutMs?: number): Promise<ArrayBuffer> {
    const resp = await this._request('GET', path, { timeoutMs });
    assertDeclaredSizeWithinCap(resp, path);
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_RESPONSE_BYTES) {
      throw oversizedError(path, buf.byteLength);
    }
    return buf;
  }

  /**
   * GET returning the raw body text (e.g. CSR PEM, AsciiDoc export).
   * `timeoutMs` overrides the default per-request timeout (use
   * `client.exportTimeout` for large exports).
   */
  async getText(
    path: string,
    accept = 'application/json',
    timeoutMs?: number,
  ): Promise<string> {
    const resp = await this._request('GET', path, { accept, timeoutMs });
    assertDeclaredSizeWithinCap(resp, path);
    const txt = await resp.text();
    if (Buffer.byteLength(txt, 'utf8') > MAX_RESPONSE_BYTES) {
      throw oversizedError(path, txt.length);
    }
    return txt;
  }

  /**
   * POST multipart/form-data (file uploads, RFC5280 decoders). Multipart bodies
   * are the large/slow operations (CRL upload, file decode), so they default to
   * the longer `exportTimeout`; pass `timeoutMs` to override.
   */
  async postMultipart<T = unknown>(
    path: string,
    parts: MultipartPart[],
    accept = 'application/json',
    timeoutMs?: number,
  ): Promise<T> {
    const formData = new UndiciFormData();
    for (const part of parts) {
      const blobPart =
        typeof part.data === 'string'
          ? part.data
          : Uint8Array.from(part.data).buffer;
      const blob = new Blob([blobPart], { type: part.mimeType });
      formData.append(part.fieldName, blob, part.filename);
    }

    await this._ensureInitialized();
    const headers = await this._auth.getHeaders();
    headers['Accept'] = accept;
    const requestId = randomUUID().slice(0, 12);
    headers['X-Request-Id'] = requestId;

    const effectiveTimeout = timeoutMs ?? this.exportTimeout;
    const start = performance.now();
    let resp: Response;
    try {
      resp = await undiciFetch(`${this._baseUrl}${path}`, {
        method: 'POST',
        headers,
        body: formData,
        dispatcher: this._agent,
        signal: AbortSignal.timeout(effectiveTimeout),
      } as UndiciRequestInit);
    } catch (err) {
      throw this._classifyTransportError(err, effectiveTimeout) ?? err;
    }

    const durationMs = Math.round(performance.now() - start);
    logger.debug(`HTTP POST ${path} -> ${resp.status} (${durationMs}ms)`, {
      request_id: requestId,
      method: 'POST',
      path,
      status: resp.status,
      duration_ms: durationMs,
    });

    if (resp.status >= 400) {
      throw parseErrorResponse(resp.status, await readErrorBodyBounded(resp));
    }
    if (resp.status === 204) return null as unknown as T;
    return readJsonBounded<T>(resp, path);
  }

  async close(): Promise<void> {
    await this._agent.close();
  }

  // -- Lazy initialization --------------------------------------------------

  private async _ensureInitialized(): Promise<void> {
    if (this._initialized) return;
    if (!this._initPromise) {
      // Reset the memoized promise if init rejects, so a later call can retry
      // rather than awaiting a permanently-rejected promise (server wedge).
      this._initPromise = this._doLazyInit().catch((err: unknown) => {
        this._initPromise = null;
        throw err;
      });
    }
    await this._initPromise;
  }

  private async _doLazyInit(): Promise<void> {
    await this._auth.refreshIfNeeded();

    // Whoami - capture principal name (best-effort; the first real tool call
    // surfaces auth errors with a precise message).
    try {
      const headers = await this._auth.getHeaders();
      const resp = await undiciFetch(
        `${this._baseUrl}/api/v1/security/principals/self`,
        {
          method: 'GET',
          headers,
          dispatcher: this._agent,
          signal: AbortSignal.timeout(this._timeout),
        },
      );
      if (resp.status === 200) {
        const principal = await readJsonBounded<Record<string, unknown>>(
          resp,
          '/api/v1/security/principals/self',
        );
        const identity = (principal['identity'] ?? {}) as Record<
          string,
          unknown
        >;
        this.principalName =
          (identity['identifier'] as string | undefined) ??
          (identity['name'] as string | undefined) ??
          'unknown';
        logger.info(`Authenticated as: ${this.principalName}`);
      } else {
        logger.warning(
          `Whoami returned ${resp.status} - continuing without principal info`,
        );
      }
    } catch (err) {
      logger.warning(`Whoami failed: ${err} - continuing`);
    }

    // License - capture Stream version (best-effort).
    try {
      const headers = await this._auth.getHeaders();
      const resp = await undiciFetch(`${this._baseUrl}/api/v1/licenses`, {
        method: 'GET',
        headers,
        dispatcher: this._agent,
        signal: AbortSignal.timeout(this._timeout),
      });
      if (resp.status === 200) {
        const license = await readJsonBounded<Record<string, unknown>>(
          resp,
          '/api/v1/licenses',
        );
        const version =
          (license['version'] as string | undefined) ??
          (license['streamVersion'] as string | undefined);
        if (version) {
          this.streamVersion = version;
          this._logVersionCompatibility(version);
        }
      }
    } catch (err) {
      logger.debug(`License lookup failed: ${err}`);
    }

    this._initialized = true;
  }

  private _logVersionCompatibility(version: string): void {
    const match = version.match(/^(\d+\.\d+)/);
    if (!match) return;
    const majorMinor = match[1]!;
    if (this._testedVersions.includes(majorMinor)) {
      logger.info(`Stream version ${version} (tested - full compatibility)`);
    } else if (this._warnVersions.includes(majorMinor)) {
      logger.warning(
        `Stream version ${version} - partially tested, some features may not work as expected`,
      );
    } else {
      logger.warning(
        `Stream version ${version} - untested, proceed with caution`,
      );
    }
  }

  // -- Internal request pipeline --------------------------------------------

  private async _request(
    method: string,
    path: string,
    opts: {
      body?: string;
      timeoutMs?: number;
      accept?: string;
      noRetry?: boolean;
    },
  ): Promise<Response> {
    const requestId = randomUUID().slice(0, 12);
    const start = performance.now();
    const timeoutMs = opts.timeoutMs ?? this._timeout;

    await this._ensureInitialized();
    const headers = await this._auth.getHeaders();
    headers['X-Request-Id'] = requestId;
    headers['Accept'] = opts.accept ?? 'application/json';

    const fetchOpts: UndiciRequestInit & { dispatcher: Agent } = {
      method,
      headers,
      dispatcher: this._agent,
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (opts.body !== undefined) {
      fetchOpts.body = opts.body;
      headers['Content-Type'] = 'application/json';
    }

    const fullUrl = `${this._baseUrl}${path}`;
    let resp: Response;
    try {
      resp = await this._doRequest(
        method,
        fullUrl,
        fetchOpts,
        timeoutMs,
        opts.noRetry,
      );
    } catch (err) {
      throw this._classifyTransportError(err, timeoutMs) ?? err;
    }

    const durationMs = Math.round(performance.now() - start);
    // Per-request success logging is DEBUG, not INFO: it is also mirrored to the
    // MCP client via notifications/message, and one INFO line per HTTP call (the
    // scaffold issues several per tool call) floods the agent session.
    logger.debug(`HTTP ${method} ${path} -> ${resp.status} (${durationMs}ms)`, {
      request_id: requestId,
      method,
      path,
      status: resp.status,
      duration_ms: durationMs,
    });

    if (resp.status >= 400) {
      throw parseErrorResponse(resp.status, await readErrorBodyBounded(resp));
    }
    return resp;
  }

  private async _doRequest(
    method: string,
    url: string,
    fetchOpts: UndiciRequestInit & { dispatcher: Agent },
    timeoutMs: number,
    noRetry?: boolean,
  ): Promise<Response> {
    const upper = method.toUpperCase();
    // Safe methods auto-retry on transient failures; mutations do not. Each
    // retry attempt needs a FRESH timeout signal (an aborted one stays aborted),
    // and it must honor the caller's timeout (e.g. exportTimeout), not the default.
    // `noRetry` opts a safe method out (e.g. a GET that triggers async work).
    if ((upper === 'GET' || upper === 'HEAD') && !noRetry) {
      return withRetry(() =>
        undiciFetch(url, {
          ...fetchOpts,
          signal: AbortSignal.timeout(timeoutMs),
        }),
      );
    }
    return undiciFetch(url, fetchOpts);
  }

  /**
   * Map a thrown fetch/transport error to a clear StreamError, or return
   * undefined to let the original error propagate. Recognizes request timeouts
   * (AbortSignal.timeout), TLS-handshake failures, and connection-level cause
   * codes; falls back to the undici "fetch failed" TypeError shape.
   */
  private _classifyTransportError(
    err: unknown,
    timeoutMs: number,
  ): StreamError | undefined {
    const name = getErrorName(err);
    if (name === 'TimeoutError' || name === 'AbortError') {
      return new StreamError(0, {
        message: `Request to ${this._baseUrl} timed out after ${timeoutMs}ms`,
        remediation:
          'Increase STREAM_TIMEOUT (or STREAM_EXPORT_TIMEOUT for large exports), ' +
          'or check that Stream is responsive.',
      });
    }

    const causeCode = getCauseCode(err);
    if (causeCode !== undefined && TLS_CAUSE_CODES.has(causeCode)) {
      return new StreamError(0, {
        message: `TLS handshake with ${this._baseUrl} failed (${causeCode})`,
        remediation:
          'Verify the Stream TLS certificate and trust chain. As a last resort ' +
          'for a known-trusted internal host, STREAM_VERIFY_SSL=false disables ' +
          'verification (never in production).',
      });
    }

    const isConnectionError =
      (causeCode !== undefined && CONNECTION_CAUSE_CODES.has(causeCode)) ||
      (causeCode === undefined &&
        err instanceof TypeError &&
        String(err).includes('fetch'));
    if (isConnectionError) {
      return new StreamError(0, {
        message: `Connection to ${this._baseUrl} failed${
          causeCode ? ` (${causeCode})` : ''
        }`,
        remediation: 'Check STREAM_URL and network connectivity.',
      });
    }

    return undefined;
  }

  private async _requestJson<T>(
    method: string,
    path: string,
    opts: { body?: string; timeoutMs?: number },
    reqOpts?: RequestOptions<T>,
  ): Promise<T> {
    const resp = await this._request(method, path, opts);
    if (resp.status === 204) return null as unknown as T;
    const parsed = await readJsonBounded<T>(resp, path);
    return reqOpts?.schema
      ? (this._validateOrThrow(reqOpts.schema, parsed, path, resp.status) as T)
      : parsed;
  }

  private _validateOrThrow<T>(
    schema: ZodType<T>,
    value: unknown,
    path: string,
    statusCode: number,
  ): T {
    const result = schema.safeParse(value);
    if (!result.success) {
      const issues = result.error.issues
        .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ');
      throw new StreamResponseValidationError({ path, statusCode, issues });
    }
    return result.data;
  }
}
