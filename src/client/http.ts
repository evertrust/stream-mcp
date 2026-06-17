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
  'UND_ERR_CONNECT_TIMEOUT',
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
  if (text.length > MAX_RESPONSE_BYTES) {
    throw new StreamError(0, {
      message: `Response from ${path} exceeds ${MAX_RESPONSE_BYTES} bytes (received: ${text.length})`,
      remediation:
        'Use a paginated endpoint or narrow the query to reduce payload size.',
    });
  }
  if (!text) return null as unknown as T;
  return JSON.parse(text) as T;
}

export interface RequestOptions<T = unknown> {
  timeout?: number;
  schema?: ZodType<T>;
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

  async getBytes(path: string): Promise<ArrayBuffer> {
    const resp = await this._request('GET', path, {});
    assertDeclaredSizeWithinCap(resp, path);
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_RESPONSE_BYTES) {
      throw oversizedError(path, buf.byteLength);
    }
    return buf;
  }

  /** GET returning the raw body text (e.g. CSR PEM, AsciiDoc export). */
  async getText(path: string, accept = 'application/json'): Promise<string> {
    const resp = await this._request('GET', path, { accept });
    assertDeclaredSizeWithinCap(resp, path);
    const txt = await resp.text();
    if (txt.length > MAX_RESPONSE_BYTES) {
      throw oversizedError(path, txt.length);
    }
    return txt;
  }

  async postText(path: string, body?: unknown): Promise<string> {
    const resp = await this._request('POST', path, {
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    return resp.text();
  }

  /** POST multipart/form-data (file uploads, RFC5280 decoders). */
  async postMultipart<T = unknown>(
    path: string,
    parts: MultipartPart[],
    accept = 'application/json',
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

    const start = performance.now();
    const resp = await undiciFetch(`${this._baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: formData,
      dispatcher: this._agent,
      signal: AbortSignal.timeout(this._timeout),
    } as UndiciRequestInit);

    const durationMs = Math.round(performance.now() - start);
    logger.info(`HTTP POST ${path} -> ${resp.status} (${durationMs}ms)`, {
      request_id: requestId,
      method: 'POST',
      path,
      status: resp.status,
      duration_ms: durationMs,
    });

    if (resp.status >= 400) {
      throw parseErrorResponse(resp.status, await resp.text());
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
    if (!this._initPromise) this._initPromise = this._doLazyInit();
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
        const principal = (await resp.json()) as Record<string, unknown>;
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
        const license = (await resp.json()) as Record<string, unknown>;
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
    opts: { body?: string; timeoutMs?: number; accept?: string },
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
      resp = await this._doRequest(method, fullUrl, fetchOpts);
    } catch (err) {
      const causeCode = getCauseCode(err);
      const isConnectionError =
        (causeCode !== undefined && CONNECTION_CAUSE_CODES.has(causeCode)) ||
        (causeCode === undefined &&
          err instanceof TypeError &&
          String(err).includes('fetch'));
      if (isConnectionError) {
        throw new StreamError(0, {
          message: `Connection to ${this._baseUrl} failed${
            causeCode ? ` (${causeCode})` : ''
          }: ${err}`,
          remediation: 'Check STREAM_URL and network connectivity.',
        });
      }
      throw err;
    }

    const durationMs = Math.round(performance.now() - start);
    logger.info(`HTTP ${method} ${path} -> ${resp.status} (${durationMs}ms)`, {
      request_id: requestId,
      method,
      path,
      status: resp.status,
      duration_ms: durationMs,
    });

    if (resp.status >= 400) {
      throw parseErrorResponse(resp.status, await resp.text());
    }
    return resp;
  }

  private async _doRequest(
    method: string,
    url: string,
    fetchOpts: UndiciRequestInit & { dispatcher: Agent },
  ): Promise<Response> {
    const upper = method.toUpperCase();
    // Safe methods auto-retry on transient failures; mutations do not.
    if (upper === 'GET' || upper === 'HEAD') {
      return withRetry(() =>
        undiciFetch(url, {
          ...fetchOpts,
          signal: AbortSignal.timeout(this._timeout),
        }),
      );
    }
    return undiciFetch(url, fetchOpts);
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
