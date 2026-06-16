import { describe, expect, it } from 'vitest';

import { loadSettings } from '../../src/settings.js';

describe('loadSettings', () => {
  it('reads STREAM_* and converts SCREAMING_SNAKE to camelCase', () => {
    const s = loadSettings({
      STREAM_URL: 'https://stream.example.com/',
      STREAM_API_ID: 'alice',
      STREAM_API_KEY: 'secret',
      STREAM_CLIENT_KEY_PASSWORD: 'pw',
    });
    expect(s.url).toBe('https://stream.example.com'); // trailing slash stripped
    expect(s.apiId).toBe('alice');
    expect(s.apiKey).toBe('secret');
    expect(s.clientKeyPassword).toBe('pw');
  });

  it('defaults apiIdprov to "local"', () => {
    expect(loadSettings({}).apiIdprov).toBe('local');
    expect(loadSettings({ STREAM_API_IDPROV: 'corp' }).apiIdprov).toBe('corp');
  });

  it('parses verifySsl truthiness', () => {
    expect(loadSettings({ STREAM_VERIFY_SSL: 'false' }).verifySsl).toBe(false);
    expect(loadSettings({ STREAM_VERIFY_SSL: '0' }).verifySsl).toBe(false);
    expect(loadSettings({ STREAM_VERIFY_SSL: 'true' }).verifySsl).toBe(true);
    expect(loadSettings({}).verifySsl).toBe(true);
  });

  it('ignores test-only STREAM_E2E_* variables', () => {
    const s = loadSettings({
      STREAM_API_ID: 'real',
      STREAM_E2E_API_ID: 'e2e',
      STREAM_E2E_API_KEY: 'x',
    });
    expect(s.apiId).toBe('real');
    expect((s as Record<string, unknown>)['e2eApiId']).toBeUndefined();
  });

  it('defaults tested versions to 2.1', () => {
    expect(loadSettings({}).testedVersions).toEqual(['2.1']);
  });
});
