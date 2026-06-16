import { describe, expect, it, vi } from 'vitest';

import { registerTriggerTools } from '../../src/tools/triggers/index.js';

interface RegisteredTool {
  name: string;
  config: any;
  handler: (...args: any[]) => any;
}

function setup() {
  const tools: RegisteredTool[] = [];
  const server = {
    registerTool: (name: string, config: any, handler: any) =>
      tools.push({ name, config, handler }),
  } as any;
  const client = {
    get: vi.fn(),
    getList: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    getText: vi.fn(),
    postMultipart: vi.fn(),
  } as any;
  registerTriggerTools(server, client);
  const byName = (n: string) => {
    const t = tools.find((x) => x.name === n);
    if (!t) throw new Error(`tool ${n} not registered`);
    return t;
  };
  return { tools, server, client, byName };
}

function parseText(result: any): any {
  return JSON.parse(result.content[0].text);
}

/** registerTool auto-converts thrown StreamErrors into isError results. */
async function expectErrorResult(
  promise: Promise<any>,
  match?: RegExp,
): Promise<void> {
  const result = await promise;
  expect(result.isError).toBe(true);
  if (match) expect(result.content[0].text).toMatch(match);
}

describe('registerTriggerTools', () => {
  it('registers exactly the 6 expected tools', () => {
    const { tools } = setup();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        'create_trigger',
        'delete_trigger',
        'get_trigger',
        'list_triggers',
        'test_trigger',
        'update_trigger',
      ].sort(),
    );
  });

  // -- list_triggers --------------------------------------------------------

  describe('list_triggers', () => {
    it('passes no params when types omitted', async () => {
      const { client, byName } = setup();
      client.getList.mockResolvedValue([{ name: 'a' }, { name: 'b' }]);
      const res = await byName('list_triggers').handler({ max_items: 50 });
      expect(client.getList).toHaveBeenCalledWith(
        '/api/v1/triggers',
        undefined,
      );
      const out = parseText(res);
      expect(out.kind).toBe('trigger');
      expect(out.count).toBe(2);
    });

    it('appends repeatable ?types= for OR-filtering', async () => {
      const { client, byName } = setup();
      client.getList.mockResolvedValue([]);
      await byName('list_triggers').handler({
        types: ['rest', 'email'],
        max_items: 50,
      });
      const [, params] = client.getList.mock.calls[0];
      expect(params).toBeInstanceOf(URLSearchParams);
      expect(params.getAll('types')).toEqual(['rest', 'email']);
    });

    it('filters by name_contains (case-insensitive)', async () => {
      const { client, byName } = setup();
      client.getList.mockResolvedValue([
        { name: 'ONERROR' },
        { name: 'ca-expiration' },
      ]);
      const res = await byName('list_triggers').handler({
        max_items: 50,
        name_contains: 'expir',
      });
      const out = parseText(res);
      expect(out.count).toBe(1);
      expect(out.items[0].name).toBe('ca-expiration');
    });
  });

  // -- get_trigger ----------------------------------------------------------

  describe('get_trigger', () => {
    it('GETs the encoded item path', async () => {
      const { client, byName } = setup();
      client.get.mockResolvedValue({ name: 'a b', type: 'email' });
      await byName('get_trigger').handler({ name: 'a b' });
      expect(client.get).toHaveBeenCalledWith('/api/v1/triggers/a%20b');
    });
  });

  // -- create_trigger -------------------------------------------------------

  describe('create_trigger', () => {
    it('maps EMAIL snake_case to camelCase wire payload', async () => {
      const { client, byName } = setup();
      client.post.mockResolvedValue({ id: 'srv', name: 'ca-mail' });
      await byName('create_trigger').handler({
        type: 'email',
        name: 'ca-mail',
        event: 'on_x509_ca_expiration',
        run_period: '5 days',
        template: {
          to: ['a@b.c'],
          from: 'noreply@x.io',
          title: 'CA Expiration',
          body: 'expires {{ca.not_before}}',
          is_html: false,
        },
        on_trigger_error: [],
      });
      const [path, body] = client.post.mock.calls[0];
      expect(path).toBe('/api/v1/triggers');
      expect(body).toEqual({
        type: 'email',
        name: 'ca-mail',
        event: 'on_x509_ca_expiration',
        runPeriod: '5 days',
        template: {
          from: 'noreply@x.io',
          title: 'CA Expiration',
          isHtml: false,
          to: ['a@b.c'],
          body: 'expires {{ca.not_before}}',
        },
        triggers: { onTriggerError: [] },
      });
    });

    it('omits runPeriod and triggers when not supplied', async () => {
      const { client, byName } = setup();
      client.post.mockResolvedValue({});
      await byName('create_trigger').handler({
        type: 'email',
        name: 'onerr',
        event: 'on_trigger_error',
        template: { from: 'a@a.a', title: 'x', is_html: true },
      });
      const [, body] = client.post.mock.calls[0];
      expect(body).not.toHaveProperty('runPeriod');
      expect(body).not.toHaveProperty('triggers');
      expect(body.template).toEqual({
        from: 'a@a.a',
        title: 'x',
        isHtml: true,
      });
    });

    it('maps REST snake_case to camelCase wire payload', async () => {
      const { client, byName } = setup();
      client.post.mockResolvedValue({ id: 'srv', name: 'ca-rest' });
      await byName('create_trigger').handler({
        type: 'rest',
        name: 'ca-rest',
        event: 'on_x509_ca_expiration',
        run_period: '5 days',
        authentication_type: 'noauth',
        method: 'POST',
        url: 'https://hook.site/x',
        payload: 'hi {{ca.not_before}}',
        payload_type: 'text',
        timeout: '30 seconds',
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        expected_http_codes: [200, 201, 204],
        on_trigger_error: [],
      });
      const [, body] = client.post.mock.calls[0];
      expect(body).toEqual({
        type: 'rest',
        name: 'ca-rest',
        event: 'on_x509_ca_expiration',
        authenticationType: 'noauth',
        method: 'POST',
        url: 'https://hook.site/x',
        expectedHttpCodes: [200, 201, 204],
        runPeriod: '5 days',
        payload: 'hi {{ca.not_before}}',
        payloadType: 'text',
        timeout: '30 seconds',
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        triggers: { onTriggerError: [] },
      });
    });

    it('rejects run_period missing on an expiration event', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'email',
          name: 'x',
          event: 'on_credentials_expiration',
          template: { from: 'a@a.a', title: 't', is_html: true },
        }),
        /run_period is mandatory/i,
      );
    });

    it('rejects run_period present on a non-expiration event', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'email',
          name: 'x',
          event: 'on_crl_gen',
          run_period: '5 days',
          template: { from: 'a@a.a', title: 't', is_html: true },
        }),
        /forbidden/i,
      );
    });

    it('rejects on_trigger_error set when event is on_trigger_error', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'email',
          name: 'x',
          event: 'on_trigger_error',
          template: { from: 'a@a.a', title: 't', is_html: true },
          on_trigger_error: ['other'],
        }),
        /on_trigger_error must not be set/i,
      );
    });

    it('rejects REST noauth with credentials', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'rest',
          name: 'x',
          event: 'on_crl_gen',
          authentication_type: 'noauth',
          credentials: 'creds',
          method: 'GET',
          url: 'http://x',
          expected_http_codes: [200],
        }),
        /credentials must not be specified/i,
      );
    });

    it('rejects REST non-noauth without credentials', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'rest',
          name: 'x',
          event: 'on_crl_gen',
          authentication_type: 'basic',
          method: 'GET',
          url: 'http://x',
          expected_http_codes: [200],
        }),
        /credentials is required/i,
      );
    });

    it('rejects REST empty expected_http_codes', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('create_trigger').handler({
          type: 'rest',
          name: 'x',
          event: 'on_crl_gen',
          authentication_type: 'noauth',
          method: 'GET',
          url: 'http://x',
          expected_http_codes: [],
        }),
        /at least one/i,
      );
    });
  });

  // -- update_trigger -------------------------------------------------------

  describe('update_trigger', () => {
    it('PUTs the full body to the collection root (no path id)', async () => {
      const { client, byName } = setup();
      client.put.mockResolvedValue({ id: 'srv', name: 'ca-rest' });
      await byName('update_trigger').handler({
        type: 'rest',
        name: 'ca-rest',
        event: 'on_crl_gen',
        authentication_type: 'noauth',
        method: 'GET',
        url: 'http://x',
        expected_http_codes: [200],
      });
      const [path, body] = client.put.mock.calls[0];
      expect(path).toBe('/api/v1/triggers');
      expect(body.name).toBe('ca-rest');
      expect(body.authenticationType).toBe('noauth');
      // full-replace: no id sent (server carries it from previous record)
      expect(body).not.toHaveProperty('id');
    });

    it('runs the same cross-field validation as create', async () => {
      const { byName } = setup();
      await expectErrorResult(
        byName('update_trigger').handler({
          type: 'email',
          name: 'x',
          event: 'on_x509_ca_expiration',
          template: { from: 'a@a.a', title: 't', is_html: true },
        }),
        /run_period is mandatory/i,
      );
    });
  });

  // -- delete_trigger -------------------------------------------------------

  describe('delete_trigger', () => {
    it('enforces the echo guard', async () => {
      const { client, byName } = setup();
      await expectErrorResult(
        byName('delete_trigger').handler({
          name: 'a',
          expected_name: 'b',
        }),
        /Safety check failed/i,
      );
      expect(client.delete).not.toHaveBeenCalled();
    });

    it('deletes the encoded item path when the guard matches', async () => {
      const { client, byName } = setup();
      client.delete.mockResolvedValue(null);
      const res = await byName('delete_trigger').handler({
        name: 'a.b',
        expected_name: 'a.b',
      });
      expect(client.delete).toHaveBeenCalledWith('/api/v1/triggers/a.b');
      expect(parseText(res)).toEqual({
        deleted: true,
        name: 'a.b',
        kind: 'trigger',
      });
    });
  });

  // -- test_trigger ---------------------------------------------------------

  describe('test_trigger', () => {
    it('PATCHes { trigger, dictionary } with the camelCase wire trigger', async () => {
      const { client, byName } = setup();
      client.patch.mockResolvedValue({ type: 'email', status: 'success' });
      await byName('test_trigger').handler({
        trigger: {
          type: 'email',
          name: 'm',
          event: 'on_crl_gen',
          template: {
            from: 'noreply@x.io',
            title: '{{x}}',
            is_html: true,
          },
        },
        dictionary: [{ key: 'x', value: 'CN=Demo' }],
      });
      const [path, body] = client.patch.mock.calls[0];
      expect(path).toBe('/api/v1/triggers');
      expect(body.trigger.template.isHtml).toBe(true);
      expect(body.trigger.type).toBe('email');
      expect(body.dictionary).toEqual([{ key: 'x', value: 'CN=Demo' }]);
    });

    it('omits dictionary when not supplied', async () => {
      const { client, byName } = setup();
      client.patch.mockResolvedValue({});
      await byName('test_trigger').handler({
        trigger: {
          type: 'email',
          name: 'm',
          event: 'on_crl_gen',
          template: { from: 'a@a.a', title: 't', is_html: false },
        },
      });
      const [, body] = client.patch.mock.calls[0];
      expect(body).not.toHaveProperty('dictionary');
    });
  });
});
