import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamClient } from '../../src/client/http.js';
import { getLiveLicense, isStreamAtLeast } from './setup.js';

/**
 * Read-only CRL series checks (Stream 2.2+, stream-offline-ca license). The
 * preview signs and stores nothing. Set STREAM_E2E_CRL_SERIES_CA to a managed
 * CA on the instance; the suite skips when it is unset, when the instance is
 * older than 2.2, or when the license does not list stream-offline-ca.
 */
const url = process.env.STREAM_E2E_URL;
const apiId = process.env.STREAM_E2E_API_ID;
const apiKey = process.env.STREAM_E2E_API_KEY;
const caName = process.env.STREAM_E2E_CRL_SERIES_CA;
const configured = Boolean(url && apiId && apiKey && caName);

const enabled =
  configured &&
  (await isStreamAtLeast(2, 2)) &&
  Boolean((await getLiveLicense())?.modules.includes('stream-offline-ca'));

const DAY_MS = 24 * 60 * 60 * 1000;

describe.skipIf(!enabled)('CRL series (live instance, Stream 2.2+)', () => {
  let client: StreamClient;

  beforeAll(() => {
    client = new StreamClient(
      url!,
      new LocalAccountAuthProvider(apiId!, apiKey!, 'local'),
      { timeout: 30, exportTimeout: 60, verifySsl: true },
    );
  });

  afterAll(async () => {
    await client?.close();
  });

  it('lists the CRL series jobs as an array', async () => {
    const jobs = await client.getList<Record<string, unknown>>(
      '/api/v1/x509/crlseries',
    );
    expect(Array.isArray(jobs)).toBe(true);
  });

  it('previews a series of dated CRLs without signing', async () => {
    const start = new Date();
    start.setUTCHours(0, 0, 0, 0);
    const end = new Date(start.getTime() + 30 * DAY_MS);
    const series = await client.post<Array<Record<string, unknown>>>(
      `/api/v1/x509/cas/${encodeURIComponent(caName!)}/crls/preview`,
      {
        start: start.toISOString(),
        end: end.toISOString(),
        overlap: '1 day',
        validity: '7 days',
      },
    );
    expect(series.length).toBeGreaterThan(0);
    expect(typeof series[0]!.thisUpdate).toBe('string');
    expect(typeof series[0]!.nextUpdate).toBe('string');
  });
});
