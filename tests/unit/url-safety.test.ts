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

  it('blocks IPv4-mapped IPv6 and NAT64 wrappers of internal addresses', () => {
    for (const u of [
      'http://[::ffff:127.0.0.1]/x', // URL parser compresses to ::ffff:7f00:1
      'http://[::ffff:169.254.169.254]/latest/meta-data', // cloud metadata
      'http://[::ffff:7f00:1]/x', // already-hex loopback
      'http://[::ffff:192.168.0.1]/x', // private
      'http://[::ffff:10.0.0.1]/x', // private
      'http://[64:ff9b::7f00:1]/x', // NAT64 loopback
    ]) {
      expect(() => assertSafeOutboundUrl(u), u).toThrow(/SSRF/i);
    }
  });

  it('still allows IPv4-mapped IPv6 of a public address', () => {
    expect(() =>
      assertSafeOutboundUrl('http://[::ffff:8.8.8.8]/x'),
    ).not.toThrow();
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
