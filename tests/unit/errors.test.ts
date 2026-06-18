import { describe, expect, it } from 'vitest';

import {
  StreamError,
  parseErrorResponse,
  redactSensitive,
  redactValue,
} from '../../src/client/errors.js';

describe('parseErrorResponse', () => {
  it('parses the standard Stream error shape', () => {
    const err = parseErrorResponse(
      404,
      JSON.stringify({
        error: 'CA-003',
        message: 'Certificate Authority not found',
        title: 'Certificate Authority not found',
        detail: 'My-CA',
        status: 404,
      }),
    );
    expect(err).toBeInstanceOf(StreamError);
    expect(err.errorCode).toBe('CA-003');
    expect(err.statusCode).toBe(404);
    expect(err.detail).toBe('My-CA');
    // -003 suffix -> "not found" remediation
    expect(err.remediation).toMatch(/Not found/i);
  });

  it('adds an auth remediation for SEC-AUTH-002', () => {
    const err = parseErrorResponse(
      401,
      JSON.stringify({
        error: 'SEC-AUTH-002',
        message: 'Invalid',
        status: 401,
      }),
    );
    expect(err.remediation).toMatch(/STREAM_API_ID/);
  });

  it('falls back gracefully for a non-JSON body', () => {
    const err = parseErrorResponse(500, 'Internal Server Error');
    expect(err.statusCode).toBe(500);
    expect(err.message).toContain('Internal Server Error');
  });

  it('surfaces a valid-JSON-but-non-object body (array / bare string) verbatim', () => {
    const arr = parseErrorResponse(422, JSON.stringify(['field x required']));
    expect(arr.statusCode).toBe(422);
    expect(arr.message).toContain('field x required');
    const str = parseErrorResponse(502, JSON.stringify('Gateway Timeout'));
    expect(str.statusCode).toBe(502);
    expect(str.message).toContain('Gateway Timeout');
  });

  it('does not attach a misleading CRUD suffix hint to security codes', () => {
    const sec = parseErrorResponse(
      404,
      JSON.stringify({ error: 'SEC-AUTH-003', message: 'no such identity' }),
    );
    // -003 must NOT become the CRUD "Not found, use list_*" hint for a SEC code.
    expect(sec.remediation).toBeUndefined();
    // ...while a real CRUD domain still gets the suffix hint.
    const crud = parseErrorResponse(
      404,
      JSON.stringify({ error: 'CA-003', message: 'not found' }),
    );
    expect(crud.remediation).toMatch(/Not found/i);
  });
});

describe('redactValue', () => {
  it('scrubs PEM private keys, JWTs, and base64 blobs', () => {
    const pem =
      '-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgk\n-----END PRIVATE KEY-----';
    expect(redactValue(`leaked: ${pem}`)).toContain('<redacted-private-key>');
    expect(
      redactValue('token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payloadpart.sig'),
    ).toContain('<redacted-jwt>');
    expect(
      redactValue('blob aGVsbG8rd29ybGQvc2VjcmV0PT1mb29iYXJiYXpxdXV4'),
    ).toContain('<redacted-blob>');
  });

  it('keeps hex identifiers (thumbprints / serials) readable', () => {
    const sha256 =
      'thumbprint a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
    expect(redactValue(sha256)).toContain(
      'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
    );
  });

  it('truncates very long strings', () => {
    // Spaced words (not one long base64 run) so truncation, not blob-redaction,
    // is what fires.
    const long = 'error detail '.repeat(50);
    const out = redactValue(long);
    expect(out.length).toBeLessThan(300);
    expect(out).toMatch(/\[truncated\]$/);
  });
});

describe('redactSensitive', () => {
  it('redacts secret-bearing fields but keeps reference names', () => {
    const out = redactSensitive({
      name: 'visible',
      keystore: 'my-keystore', // reference name -> visible
      password: 'hunter2',
      pin: { clear: 'abc' },
      nested: { secret: 'x', label: 'ok' },
    }) as Record<string, any>;
    expect(out.name).toBe('visible');
    expect(out.keystore).toBe('my-keystore');
    expect(out.password).toBe('<redacted>');
    expect(out.pin).toBe('<redacted>');
    expect(out.nested.secret).toBe('<redacted>');
    expect(out.nested.label).toBe('ok');
  });

  it('redacts both halves of the {clear, secure} secret object', () => {
    // `holder` is not itself a sensitive field, so it survives while both
    // secret-bearing children are redacted.
    const out = redactSensitive({
      holder: { clear: 'plain', secure: 'AQID...ciphertext', label: 'ok' },
    }) as Record<string, any>;
    expect(out.holder.label).toBe('ok');
    expect(out.holder.clear).toBe('<redacted>');
    expect(out.holder.secure).toBe('<redacted>');
  });

  it('recurses into arrays of objects', () => {
    const out = redactSensitive({
      items: [{ name: 'ok', password: 'p1' }, { token: 't2' }],
    }) as Record<string, any>;
    expect(out.items[0].name).toBe('ok');
    expect(out.items[0].password).toBe('<redacted>');
    expect(out.items[1].token).toBe('<redacted>');
  });
});
