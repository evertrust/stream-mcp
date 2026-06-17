/**
 * Client-side SSRF guard for outbound URLs that Stream itself will fetch
 * (e.g. REST notification triggers — Stream performs the request and, for
 * test_trigger, returns the response body). This blocks the classic SSRF
 * targets (loopback, link-local / cloud metadata, private and CGNAT ranges)
 * before create/update/test reaches the server.
 *
 * This is defense-in-depth: the authoritative control lives in Stream. We can
 * only inspect literal hosts (IP literals / "localhost"); DNS names and
 * TemplateString hosts (`{{var}}`) cannot be resolved here and are allowed with
 * the scheme enforced. Set STREAM_ALLOW_INTERNAL_URLS=true to disable the guard
 * (e.g. for legitimate internal webhooks).
 */
import { StreamError } from '../client/errors.js';

function internalAllowed(): boolean {
  const v = (process.env['STREAM_ALLOW_INTERNAL_URLS'] ?? '').toLowerCase();
  return v === 'true' || v === '1' || v === 'yes';
}

/** True if an IPv4 literal is loopback / private / link-local / reserved. */
function ipv4IsInternal(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const octets = m.slice(1).map((s) => Number(s));
  if (octets.some((n) => n > 255)) return false; // not a valid v4 literal
  const [a, b] = octets as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  return false;
}

/** True if a literal host is loopback / link-local / private (best-effort). */
function hostIsInternal(rawHost: string): boolean {
  const h = rawHost.toLowerCase().replace(/^\[/, '').replace(/\]$/, '');
  if (!h) return true; // empty host
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  // IPv6
  if (h === '::1' || h === '::') return true; // loopback / unspecified
  if (h.startsWith('fe80:')) return true; // link-local
  if (h.startsWith('fc') || h.startsWith('fd')) return true; // unique local fc00::/7
  if (h.startsWith('::ffff:')) return ipv4IsInternal(h.slice('::ffff:'.length));
  // IPv4
  return ipv4IsInternal(h);
}

/**
 * Throw StreamError(422) if `rawUrl` is not an http(s) URL or points at an
 * internal/reserved host. No-op when STREAM_ALLOW_INTERNAL_URLS is set or when
 * the host is a DNS name / TemplateString placeholder we cannot resolve here.
 */
export function assertSafeOutboundUrl(rawUrl: string, label = 'url'): void {
  if (internalAllowed()) return;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // Not a parseable absolute URL (often a TemplateString). Enforce the scheme
    // at least; the host cannot be inspected.
    if (!/^https?:\/\//i.test(rawUrl)) {
      throw new StreamError(422, {
        errorCode: 'URL-SCHEME',
        message: `${label} must be an absolute http:// or https:// URL.`,
        remediation: 'Provide an absolute http(s) URL.',
      });
    }
    return;
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new StreamError(422, {
      errorCode: 'URL-SCHEME',
      message: `${label} must use http or https (got "${parsed.protocol}").`,
      remediation: 'Use an http:// or https:// URL.',
    });
  }

  const host = parsed.hostname;
  if (host.includes('{') || host.includes('}')) return; // templated host — cannot validate

  if (hostIsInternal(host)) {
    throw new StreamError(422, {
      errorCode: 'SSRF-BLOCKED',
      message:
        `${label} targets a loopback/link-local/private address ("${host}"), ` +
        'which is blocked to prevent server-side request forgery.',
      remediation:
        'Use a public URL. To allow internal targets (e.g. an internal webhook), ' +
        'set STREAM_ALLOW_INTERNAL_URLS=true on the MCP server (use with caution).',
    });
  }
}
