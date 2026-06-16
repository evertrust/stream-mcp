import { describe, expect, it } from 'vitest';

import { createAuthProvider } from '../../src/auth/index.js';
import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { loadSettings } from '../../src/settings.js';

describe('LocalAccountAuthProvider', () => {
  it('emits the three Stream auth headers', async () => {
    const p = new LocalAccountAuthProvider('alice', 'secret', 'local');
    expect(await p.getHeaders()).toEqual({
      'X-API-ID': 'alice',
      'X-API-KEY': 'secret',
      'X-API-IDPROV': 'local',
    });
  });

  it('throws when credentials are missing', () => {
    expect(() => new LocalAccountAuthProvider('', '')).toThrow(/STREAM_API_ID/);
  });
});

describe('createAuthProvider', () => {
  it('selects local-account auth when API id/key are set', async () => {
    const p = createAuthProvider(
      loadSettings({ STREAM_API_ID: 'a', STREAM_API_KEY: 'b' }),
    );
    expect(p).toBeInstanceOf(LocalAccountAuthProvider);
    expect(await p.getHeaders()).toMatchObject({ 'X-API-ID': 'a' });
  });

  it('throws when no auth is configured', () => {
    expect(() => createAuthProvider(loadSettings({}))).toThrow(
      /No authentication configured/,
    );
  });

  it('rejects setting both cert and pfx', () => {
    expect(() =>
      createAuthProvider(
        loadSettings({
          STREAM_CLIENT_CERT: '/tmp/c.crt',
          STREAM_CLIENT_PFX: '/tmp/c.p12',
        }),
      ),
    ).toThrow(/not both/);
  });
});
