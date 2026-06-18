import { afterEach, describe, expect, it, vi } from 'vitest';

import { withRetry } from '../../src/client/retry.js';

/** Minimal Response-like stub with a cancellable body (for drain assertions). */
function resp(
  status: number,
  headers: Record<string, string> = {},
): Response & { _cancel: ReturnType<typeof vi.fn> } {
  const cancel = vi.fn().mockResolvedValue(undefined);
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
  return {
    status,
    headers: { get: (k: string) => lower[k.toLowerCase()] ?? null },
    body: { cancel },
    _cancel: cancel,
  } as unknown as Response & { _cancel: ReturnType<typeof vi.fn> };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function settle<T>(promise: Promise<T>): Promise<T> {
  // Register a handler so a rejection during the timer flush is not reported as
  // an unhandled rejection; the caller still awaits `promise` for the real
  // assertion.
  promise.catch(() => {});
  // Flush the backoff timers + their microtasks.
  await vi.runAllTimersAsync();
  return promise;
}

describe('withRetry', () => {
  it('retries a 503 then returns the eventual 200', async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn()
      .mockResolvedValueOnce(resp(503))
      .mockResolvedValueOnce(resp(200));
    const result = await settle(withRetry(fn));
    expect(result.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('returns the last retryable response after exhausting attempts (does not throw)', async () => {
    vi.useFakeTimers();
    const fn = vi.fn().mockResolvedValue(resp(503));
    const result = await settle(withRetry(fn, { maxAttempts: 3 }));
    expect(result.status).toBe(503);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('does not retry a non-retryable status (400)', async () => {
    vi.useFakeTimers();
    const fn = vi.fn().mockResolvedValue(resp(400));
    const result = await settle(withRetry(fn));
    expect(result.status).toBe(400);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('drains the body of a discarded retryable response (releases the connection)', async () => {
    vi.useFakeTimers();
    const first = resp(503);
    const fn = vi
      .fn()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(resp(200));
    await settle(withRetry(fn));
    expect(first._cancel).toHaveBeenCalledTimes(1);
  });

  it('honors and clamps a pathological Retry-After on 429', async () => {
    vi.useFakeTimers();
    // Astronomical Retry-After must clamp to maxDelayMs (10s by default), so
    // the timers still resolve when fully advanced.
    const fn = vi
      .fn()
      .mockResolvedValueOnce(resp(429, { 'Retry-After': '999999' }))
      .mockResolvedValueOnce(resp(200));
    const result = await settle(withRetry(fn));
    expect(result.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('falls back to backoff on a non-numeric Retry-After', async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn()
      .mockResolvedValueOnce(resp(429, { 'Retry-After': 'Wed, 21 Oct 2099' }))
      .mockResolvedValueOnce(resp(200));
    const result = await settle(withRetry(fn));
    expect(result.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries a thrown connection error then succeeds', async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn()
      .mockRejectedValueOnce(new Error('ECONNRESET'))
      .mockResolvedValueOnce(resp(200));
    const result = await settle(withRetry(fn));
    expect(result.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('rethrows the last error when connection errors persist', async () => {
    vi.useFakeTimers();
    const boom = new Error('ECONNREFUSED');
    const fn = vi.fn().mockRejectedValue(boom);
    await expect(settle(withRetry(fn, { maxAttempts: 2 }))).rejects.toBe(boom);
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
