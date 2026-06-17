import { afterEach, describe, expect, it } from 'vitest';

import { assertSafeOutboundUrl } from '../../src/tools/url-safety.js';

afterEach(() => {
  delete process.env.STREAM_ALLOW_INTERNAL_URLS;
});

describe('assertSafeOutboundUrl (SSRF guard)', () => {
  it('allows public http(s) URLs', () => {
    expect(() =>
      assertSafeOutboundUrl('https://hooks.example.com/x'),
    ).not.toThrow();
    expect(() => assertSafeOutboundUrl('http://1.2.3.4/notify')).not.toThrow();
  });

  it('blocks loopback, link-local/metadata, and private targets', () => {
    for (const u of [
      'http://localhost/x',
      'http://127.0.0.1/x',
      'https://169.254.169.254/latest/meta-data',
      'http://10.1.2.3/x',
      'http://192.168.0.5/x',
      'http://172.16.5.5/x',
      'http://[::1]/x',
    ]) {
      expect(() => assertSafeOutboundUrl(u), u).toThrow(/SSRF|http/i);
    }
  });

  it('blocks non-http(s) schemes', () => {
    expect(() => assertSafeOutboundUrl('file:///etc/passwd')).toThrow();
    expect(() => assertSafeOutboundUrl('gopher://1.2.3.4/')).toThrow();
  });

  it('allows internal targets when STREAM_ALLOW_INTERNAL_URLS is set', () => {
    process.env.STREAM_ALLOW_INTERNAL_URLS = 'true';
    expect(() => assertSafeOutboundUrl('http://127.0.0.1/x')).not.toThrow();
    expect(() => assertSafeOutboundUrl('http://10.0.0.1/x')).not.toThrow();
  });

  it('allows TemplateString hosts it cannot resolve (scheme still enforced)', () => {
    expect(() =>
      assertSafeOutboundUrl('https://{{host}}/notify'),
    ).not.toThrow();
  });
});
