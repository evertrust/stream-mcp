import { describe, expect, it } from 'vitest';

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamClient } from '../../src/client/http.js';

const url = process.env.STREAM_E2E_URL;
const apiId = process.env.STREAM_E2E_API_ID;
const apiKey = process.env.STREAM_E2E_API_KEY;
const live = Boolean(url && apiId && apiKey);

describe.skipIf(!live)('foundation (live QA)', () => {
  function client(): StreamClient {
    return new StreamClient(
      url!,
      new LocalAccountAuthProvider(apiId!, apiKey!, 'local'),
      { timeout: 30, exportTimeout: 60, verifySsl: true },
    );
  }

  it('authenticates and resolves the current principal', async () => {
    const self = await client().get<Record<string, any>>(
      '/api/v1/security/principals/self',
    );
    expect(self.identity?.identifier).toBeTruthy();
  });

  it('lists CAs, mapping 204/empty to an array', async () => {
    const cas = await client().getList<Record<string, unknown>>('/api/v1/cas');
    expect(Array.isArray(cas)).toBe(true);
  });

  it('surfaces a StreamError with an error code on 404', async () => {
    await expect(
      client().get('/api/v1/cas/__definitely_missing__'),
    ).rejects.toMatchObject({ name: 'StreamError', statusCode: 404 });
  });
});
