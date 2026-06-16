import { describe, expect, it } from 'vitest';

import {
  StreamError,
  parseErrorResponse,
  redactSensitive,
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
});
