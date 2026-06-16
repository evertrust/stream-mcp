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
});
