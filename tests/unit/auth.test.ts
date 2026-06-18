import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { createAuthProvider } from '../../src/auth/index.js';
import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { MtlsAuthProvider } from '../../src/auth/mtls.js';
import { loadSettings } from '../../src/settings.js';

const dir = mkdtempSync(join(tmpdir(), 'stream-mtls-'));
const CERT = join(dir, 'client.crt');
const KEY = join(dir, 'client.key');
const PFX = join(dir, 'client.p12');
writeFileSync(CERT, 'CERTDATA');
writeFileSync(KEY, 'KEYDATA');
writeFileSync(PFX, Buffer.from([1, 2, 3, 4]));

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

  it('selects mTLS when a client cert is set on an https URL', () => {
    const p = createAuthProvider(
      loadSettings({
        STREAM_URL: 'https://stream.test',
        STREAM_CLIENT_CERT: CERT,
        STREAM_CLIENT_KEY: KEY,
      }),
    );
    expect(p).toBeInstanceOf(MtlsAuthProvider);
  });

  it('rejects mTLS on a non-https STREAM_URL (cert would be silently dropped)', () => {
    expect(() =>
      createAuthProvider(
        loadSettings({
          STREAM_URL: 'http://stream.test',
          STREAM_CLIENT_CERT: CERT,
          STREAM_CLIENT_KEY: KEY,
        }),
      ),
    ).toThrow(/https/i);
  });
});

describe('MtlsAuthProvider', () => {
  it('emits PEM cert/key/passphrase as dispatcher connect options', () => {
    const p = new MtlsAuthProvider({
      certPath: CERT,
      keyPath: KEY,
      keyPassword: 'pw',
    });
    const opts = p.getDispatcherOptions() as Record<string, unknown>;
    expect(opts.cert).toBe('CERTDATA');
    expect(opts.key).toBe('KEYDATA');
    expect(opts.passphrase).toBe('pw');
  });

  it('emits PFX bytes as dispatcher connect options', () => {
    const p = new MtlsAuthProvider({ pfxPath: PFX, pfxPassword: 'pw' });
    const opts = p.getDispatcherOptions() as Record<string, unknown>;
    expect(Buffer.isBuffer(opts.pfx)).toBe(true);
    expect(opts.passphrase).toBe('pw');
  });

  it('sends no auth headers (the certificate is the credential)', async () => {
    const p = new MtlsAuthProvider({ certPath: CERT, keyPath: KEY });
    expect(await p.getHeaders()).toEqual({});
  });

  it('throws a clear error when the cert file is unreadable', () => {
    expect(
      () => new MtlsAuthProvider({ certPath: '/no/such.crt', keyPath: KEY }),
    ).toThrow(/STREAM_CLIENT_CERT/);
  });

  it('throws when a cert is set without a key', () => {
    expect(() => new MtlsAuthProvider({ certPath: CERT })).toThrow(
      /STREAM_CLIENT_KEY/,
    );
  });
});
