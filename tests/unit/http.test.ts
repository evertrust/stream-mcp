import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock only undici.fetch; keep Agent/FormData real (Agent never connects
// because fetch is mocked). `vi.hoisted` makes fetchMock available to the
// hoisted vi.mock factory.
const { fetchMock } = vi.hoisted(() => ({ fetchMock: vi.fn() }));
vi.mock('undici', async (importOriginal) => {
  const actual = await importOriginal<typeof import('undici')>();
  return { ...actual, fetch: fetchMock };
});

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamError } from '../../src/client/errors.js';
import { StreamClient } from '../../src/client/http.js';

function route(handler: (url: string, init: any) => Response): void {
  fetchMock.mockImplementation(async (input: any, init: any) => {
    const url: string =
      typeof input === 'string' ? input : (input?.url ?? String(input ?? ''));
    // Lazy-init calls (whoami + license) get benign 200s.
    if (url.endsWith('/api/v1/security/principals/self')) {
      return new Response(
        JSON.stringify({ identity: { identifier: 'tester' } }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (url.endsWith('/api/v1/licenses')) {
      return new Response(JSON.stringify({ version: '2.1.9' }), {
        status: 200,
      });
    }
    return handler(url, init);
  });
}

function makeClient(): StreamClient {
  return new StreamClient(
    'https://stream.test',
    new LocalAccountAuthProvider('a', 'b', 'local'),
    { timeout: 5, exportTimeout: 5, verifySsl: true },
  );
}

describe('StreamClient', () => {
  beforeEach(() => fetchMock.mockReset());

  it('getList maps 204 to an empty array', async () => {
    route(() => new Response(null, { status: 204 }));
    const items = await makeClient().getList('/api/v1/cas');
    expect(items).toEqual([]);
  });

  it('getList returns the array on 200', async () => {
    route(
      () =>
        new Response(JSON.stringify([{ name: 'a' }, { name: 'b' }]), {
          status: 200,
        }),
    );
    const items = await makeClient().getList<{ name: string }>('/api/v1/cas');
    expect(items.map((i) => i.name)).toEqual(['a', 'b']);
  });

  it('get parses a single object', async () => {
    route(() => new Response(JSON.stringify({ name: 'x' }), { status: 200 }));
    const obj = await makeClient().get<{ name: string }>('/api/v1/cas/x');
    expect(obj.name).toBe('x');
  });

  it('throws StreamError on an error status', async () => {
    route(
      () =>
        new Response(
          JSON.stringify({
            error: 'CA-003',
            message: 'not found',
            status: 404,
          }),
          { status: 404 },
        ),
    );
    await expect(makeClient().get('/api/v1/cas/missing')).rejects.toMatchObject(
      {
        name: 'StreamError',
        errorCode: 'CA-003',
        statusCode: 404,
      },
    );
  });

  it('post sends a JSON body', async () => {
    let captured: any;
    route((_url, init) => {
      captured = init;
      return new Response(JSON.stringify({ ok: true }), { status: 201 });
    });
    await makeClient().post('/api/v1/cas', { name: 'new' });
    expect(captured.method).toBe('POST');
    expect(JSON.parse(captured.body)).toEqual({ name: 'new' });
    expect(captured.headers['X-API-ID']).toBe('a');
  });

  it('exposes StreamError as the thrown type', async () => {
    route(
      () =>
        new Response(JSON.stringify({ error: 'CA-002', status: 400 }), {
          status: 400,
        }),
    );
    await expect(makeClient().get('/api/v1/cas/x')).rejects.toBeInstanceOf(
      StreamError,
    );
  });

  it('getText rejects an oversized Content-Length before reading the body', async () => {
    const huge = String(11 * 1024 * 1024);
    route(
      () =>
        ({
          status: 200,
          headers: {
            get: (k: string) => (k === 'content-length' ? huge : null),
          },
          text: async () => 'should-not-be-read',
        }) as any,
    );
    await expect(makeClient().getText('/api/v1/adoc')).rejects.toMatchObject({
      name: 'StreamError',
    });
  });

  it('getBytes rejects an oversized actual body even without Content-Length', async () => {
    route(
      () =>
        ({
          status: 200,
          headers: { get: () => null },
          arrayBuffer: async () => new ArrayBuffer(11 * 1024 * 1024),
        }) as any,
    );
    await expect(makeClient().getBytes('/api/v1/x')).rejects.toMatchObject({
      name: 'StreamError',
    });
  });

  it('captures the principal name and Stream version during lazy init', async () => {
    route(() => new Response(JSON.stringify([]), { status: 200 }));
    const c = makeClient();
    await c.getList('/api/v1/cas');
    expect(c.principalName).toBe('tester');
    expect(c.streamVersion).toBe('2.1.9');
  });

  it('falls back to principalName "unknown" when identity has no identifier/name', async () => {
    fetchMock.mockImplementation(async (input: any) => {
      const url = typeof input === 'string' ? input : String(input?.url ?? '');
      if (url.endsWith('/api/v1/security/principals/self')) {
        return new Response(JSON.stringify({ identity: {} }), { status: 200 });
      }
      if (url.endsWith('/api/v1/licenses')) {
        return new Response(JSON.stringify({ version: '2.1.9' }), {
          status: 200,
        });
      }
      return new Response(JSON.stringify([]), { status: 200 });
    });
    const c = makeClient();
    await c.getList('/api/v1/cas');
    expect(c.principalName).toBe('unknown');
  });

  it('logs a tested Stream version as fully compatible', async () => {
    const writeSpy = vi
      .spyOn(process.stderr, 'write')
      .mockReturnValue(true as any);
    route(() => new Response(JSON.stringify([]), { status: 200 }));
    const c = new StreamClient(
      'https://stream.test',
      new LocalAccountAuthProvider('a', 'b', 'local'),
      {
        timeout: 5,
        exportTimeout: 5,
        verifySsl: true,
        testedVersions: ['2.1'],
      },
    );
    await c.getList('/api/v1/cas');
    const logs = writeSpy.mock.calls.map((c) => String(c[0])).join('');
    expect(logs).toContain('tested - full compatibility');
    writeSpy.mockRestore();
  });

  it('classifies a connection-refused error with a STREAM_URL hint', async () => {
    route((_url, init) => {
      if (init?.method === 'POST') {
        const e: any = new Error('connect failed');
        e.cause = { code: 'ECONNREFUSED' };
        throw e;
      }
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await expect(
      makeClient().post('/api/v1/cas', { name: 'x' }),
    ).rejects.toMatchObject({
      name: 'StreamError',
      remediation: expect.stringContaining('STREAM_URL'),
    });
  });

  it('classifies a request timeout (AbortSignal.timeout) with a timeout hint', async () => {
    route((_url, init) => {
      if (init?.method === 'POST') {
        const e: any = new Error('aborted');
        e.name = 'TimeoutError';
        throw e;
      }
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await expect(
      makeClient().post('/api/v1/cas', { name: 'x' }),
    ).rejects.toMatchObject({
      name: 'StreamError',
      remediation: expect.stringContaining('STREAM_TIMEOUT'),
    });
  });

  it('classifies a TLS handshake failure with a TLS hint', async () => {
    route((_url, init) => {
      if (init?.method === 'POST') {
        const e: any = new Error('tls');
        e.cause = { code: 'CERT_HAS_EXPIRED' };
        throw e;
      }
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await expect(
      makeClient().post('/api/v1/cas', { name: 'x' }),
    ).rejects.toMatchObject({
      name: 'StreamError',
      remediation: expect.stringContaining('TLS'),
    });
  });

  it('does not retry a mutation (POST) on a 503', async () => {
    let postCalls = 0;
    route((_url, init) => {
      if (init?.method === 'POST') {
        postCalls += 1;
        return new Response(JSON.stringify({ error: 'X-001' }), {
          status: 503,
        });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await expect(makeClient().post('/api/v1/cas', {})).rejects.toMatchObject({
      statusCode: 503,
    });
    expect(postCalls).toBe(1);
  });

  it('does not retry a GET marked noRetry on a 503', async () => {
    let getCalls = 0;
    route((url) => {
      if (url.endsWith('/api/v1/cas/x/crl')) {
        getCalls += 1;
        return new Response(JSON.stringify({ error: 'X-001' }), {
          status: 503,
        });
      }
      return new Response(JSON.stringify({}), { status: 200 });
    });
    await expect(
      makeClient().get('/api/v1/cas/x/crl', undefined, { noRetry: true }),
    ).rejects.toMatchObject({ statusCode: 503 });
    expect(getCalls).toBe(1);
  });
});
