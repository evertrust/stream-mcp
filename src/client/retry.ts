import { getLogger } from '../logging.js';

const logger = getLogger('stream_mcp.client.retry');

const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);

export interface RetryOptions {
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
}

/**
 * Release the socket back to the undici pool for a response we are about to
 * discard. undici requires every response body to be fully consumed or
 * cancelled; otherwise the connection leaks. Cancelling the stream avoids
 * buffering a (potentially large) error page.
 */
async function drainBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    /* already consumed / no body - nothing to release */
  }
}

/**
 * Apply "equal jitter" (50-100% of the computed delay) so concurrent clients
 * retrying the same overloaded backend do not synchronize into a thundering
 * herd. Server-provided Retry-After values are honored verbatim (no jitter).
 */
function jitter(delayMs: number): number {
  return Math.round(delayMs * (0.5 + Math.random() * 0.5));
}

/**
 * Retry a fetch thunk with exponential backoff.
 * Only retries on retryable status codes and connection errors.
 * Respects Retry-After header on 429 responses.
 */
export async function withRetry(
  fn: () => Promise<Response>,
  opts: RetryOptions = {},
): Promise<Response> {
  const maxAttempts = opts.maxAttempts ?? 3;
  const baseDelayMs = opts.baseDelayMs ?? 1000;
  const maxDelayMs = opts.maxDelayMs ?? 10000;

  let lastError: unknown;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const response = await fn();

      // Check status BEFORE consuming body
      if (!RETRYABLE_STATUSES.has(response.status) || attempt === maxAttempts) {
        return response;
      }

      // Retryable status - compute jittered exponential backoff.
      let delayMs = jitter(
        Math.min(baseDelayMs * Math.pow(2, attempt - 1), maxDelayMs),
      );

      // Respect Retry-After header on 429 (verbatim, clamped, no jitter).
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        if (retryAfter) {
          const retryAfterSeconds = parseInt(retryAfter, 10);
          if (!isNaN(retryAfterSeconds)) {
            // Clamp to [0, maxDelayMs/1000] to defend against
            // pathological server responses (negative or astronomical).
            const maxRetryAfterSeconds = Math.floor(maxDelayMs / 1000);
            const clamped = Math.min(
              Math.max(retryAfterSeconds, 0),
              maxRetryAfterSeconds,
            );
            delayMs = clamped * 1000;
          } else {
            logger.warning(
              `Invalid Retry-After header '${retryAfter}' - falling back to exponential delay`,
            );
          }
        }
      }

      logger.info(
        `Retryable status ${response.status} (attempt ${attempt}/${maxAttempts}), retrying in ${delayMs}ms`,
      );
      // Release the connection for this discarded response before backing off.
      await drainBody(response);
      await sleep(delayMs);
    } catch (err) {
      lastError = err;
      if (attempt === maxAttempts) break;

      const delayMs = jitter(
        Math.min(baseDelayMs * Math.pow(2, attempt - 1), maxDelayMs),
      );
      logger.info(
        `Connection error (attempt ${attempt}/${maxAttempts}), retrying in ${delayMs}ms: ${err}`,
      );
      await sleep(delayMs);
    }
  }

  throw lastError;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
