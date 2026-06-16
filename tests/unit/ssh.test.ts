import { describe, expect, it, vi } from 'vitest';

import { registerSshTools } from '../../src/tools/ssh/index.js';

// ---------------------------------------------------------------------------
// Mock harness: capture registered tools, invoke handlers directly.
// ---------------------------------------------------------------------------

interface RegisteredTool {
  n: string;
  c: any;
  h: (args: any) => Promise<{ content: { type: string; text: string }[] }>;
}

function setup() {
  const calls: RegisteredTool[] = [];
  const server = {
    registerTool: (n: string, c: any, h: any) => calls.push({ n, c, h }),
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
  };
  registerSshTools(server, client as any);
  const byName = (name: string): RegisteredTool => {
    const t = calls.find((c) => c.n === name);
    if (!t) throw new Error(`tool ${name} not registered`);
    return t;
  };
  return { calls, client, byName };
}

async function textOf(
  result: Promise<{ content: { type: string; text: string }[] }>,
): Promise<string> {
  const r = await result;
  return r.content[0]!.text;
}

const ALL_TOOLS = [
  'list_ssh_cas',
  'get_ssh_ca',
  'create_ssh_ca',
  'update_ssh_ca',
  'delete_ssh_ca',
  'generate_krl',
  'list_ssh_templates',
  'get_ssh_template',
  'create_ssh_template',
  'update_ssh_template',
  'delete_ssh_template',
  'search_ssh_certificates',
  'aggregate_ssh_certificates',
  'get_ssh_certificate',
  'enroll_ssh_certificate',
  'revoke_ssh_certificate',
  'list_requestable_ssh_templates',
  'list_krls',
  'get_krl',
];

describe('ssh registration', () => {
  it('registers all 19 required tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    for (const t of ALL_TOOLS) {
      expect(names, `missing ${t}`).toContain(t);
    }
    // No stray tools beyond the 19.
    expect(calls).toHaveLength(ALL_TOOLS.length);
  });
});

// ---------------------------------------------------------------------------
// SSH CAs
// ---------------------------------------------------------------------------

describe('list_ssh_cas / get_ssh_ca', () => {
  it('list_ssh_cas uses getList (204 -> [])', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    await byName('list_ssh_cas').h({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/ssh/cas');
  });

  it('get_ssh_ca encodes the name into the item path', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({ name: 'My CA' });
    await byName('get_ssh_ca').h({ name: 'My CA' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/ssh/cas/My%20CA');
  });
});

describe('create_ssh_ca', () => {
  it('POSTs the CA body with camelCase wire fields and never sends publicKey', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({
      name: 'my-ssh-ca',
      publicKey: 'ssh-rsa AAAA',
    });
    await byName('create_ssh_ca').h({
      name: 'my-ssh-ca',
      private_key: {
        keystore: 'SSH',
        name: 'my-ssh-ca',
        hash_algorithm: 'SHA256',
      },
      enroll: true,
      enforce_key_unicity: false,
      krl_policy: { validity: '14 days' },
    });
    expect(client.post).toHaveBeenCalledTimes(1);
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/cas');
    expect(body).toEqual({
      name: 'my-ssh-ca',
      privateKey: {
        keystore: 'SSH',
        name: 'my-ssh-ca',
        hashAlgorithm: 'SHA256',
      },
      enroll: true,
      enforceKeyUnicity: false,
      krlPolicy: { validity: '14 days' },
    });
    expect('publicKey' in body).toBe(false);
  });

  it('maps nested override/triggers/krlPolicy + usePSS to camelCase', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'sma-rsa' });
    await byName('create_ssh_ca').h({
      name: 'sma-rsa',
      private_key: { keystore: 'SSH', name: 'sma-rsa', use_pss: true },
      enroll: true,
      enforce_key_unicity: true,
      override_permissions: { type: true, backdate: true, lifetime: true },
      triggers: { on_krl_generation: ['t1'], on_krl_sync_error: ['t2'] },
      krl_policy: {
        validity: '14 days',
        hard_generation: '0 0 0/4 * * ?',
        lazy_generation: '0 0 0/1 * * ?',
      },
    });
    const body = client.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body['privateKey']).toEqual({
      keystore: 'SSH',
      name: 'sma-rsa',
      usePSS: true,
    });
    expect(body['overridePermissions']).toEqual({
      type: true,
      backdate: true,
      lifetime: true,
    });
    expect(body['triggers']).toEqual({
      onKRLGeneration: ['t1'],
      onKRLSyncError: ['t2'],
    });
    expect(body['krlPolicy']).toEqual({
      validity: '14 days',
      hardGeneration: '0 0 0/4 * * ?',
      lazyGeneration: '0 0 0/1 * * ?',
    });
  });
});

describe('update_ssh_ca', () => {
  it('GET-strip-merge-PUTs: strips id/publicKey, PUTs collection root', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'sma-rsa',
      publicKey: 'ssh-rsa AAAA...', // server-derived -> must be stripped
      privateKey: { keystore: 'SSH', name: 'sma-rsa', hashAlgorithm: 'SHA256' },
      enroll: true,
      enforceKeyUnicity: false,
      krlPolicy: { validity: '14 days' },
    });
    let putPath: string | undefined;
    let putBody: any;
    client.put.mockImplementation(async (p: string, b: any) => {
      putPath = p;
      putBody = b;
      return { ...b };
    });

    await byName('update_ssh_ca').h({
      name: 'sma-rsa',
      enroll: false,
      enforce_key_unicity: true,
    });

    expect(client.get).toHaveBeenCalledWith('/api/v1/ssh/cas/sma-rsa');
    expect(putPath).toBe('/api/v1/ssh/cas'); // PUT on collection root
    // server-managed fields stripped
    expect(putBody.id).toBeUndefined();
    expect(putBody.publicKey).toBeUndefined();
    // overrides applied (camelCase)
    expect(putBody.enroll).toBe(false);
    expect(putBody.enforceKeyUnicity).toBe(true);
    // preserved from previous
    expect(putBody.name).toBe('sma-rsa');
    expect(putBody.privateKey).toEqual({
      keystore: 'SSH',
      name: 'sma-rsa',
      hashAlgorithm: 'SHA256',
    });
  });

  it('rejects clear_fields targeting publicKey (server-managed)', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('update_ssh_ca').h({
        name: 'sma-rsa',
        clear_fields: ['publicKey'],
      }),
    );
    expect(out).toContain('publicKey');
    expect(client.put).not.toHaveBeenCalled();
  });
});

describe('delete_ssh_ca', () => {
  it('enforces the expected_name echo guard', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('delete_ssh_ca').h({ name: 'CA1', expected_name: 'WRONG' }),
    );
    expect(out).toContain('Safety check failed');
    expect(client.delete).not.toHaveBeenCalled();
  });

  it('deletes with matching echo and encodes the path', async () => {
    const { client, byName } = setup();
    client.delete.mockResolvedValue(null);
    await byName('delete_ssh_ca').h({ name: 'CA 1', expected_name: 'CA 1' });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/ssh/cas/CA%201');
  });
});

// ---------------------------------------------------------------------------
// KRL
// ---------------------------------------------------------------------------

describe('generate_krl', () => {
  it('GETs :name/krl with no lazy param by default', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue(null); // 204
    await byName('generate_krl').h({ name: 'sma-rsa' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/ssh/cas/sma-rsa/krl',
      undefined,
    );
  });

  it('GETs :name/krl?lazy=true when lazy=true', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue(null);
    await byName('generate_krl').h({ name: 'sma-rsa', lazy: true });
    const [path, params] = client.get.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/cas/sma-rsa/krl');
    expect((params as URLSearchParams).toString()).toBe('lazy=true');
  });
});

describe('list_krls / get_krl', () => {
  it('list_krls uses getList (204 -> [])', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    await byName('list_krls').h({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/ssh/krls');
  });

  it('get_krl GETs /ssh/krls/:ca with the encoded ca', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({ ca: 'sma-rsa', number: 2048 });
    await byName('get_krl').h({ ca: 'sma rsa' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/ssh/krls/sma%20rsa');
  });
});

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

describe('create_ssh_template', () => {
  it('POSTs the template body with camelCase fields', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'user-tpl' });
    await byName('create_ssh_template').h({
      name: 'user-tpl',
      enabled: true,
      type: 'USER',
      lifetime: '30 days',
      backdate: '5 minutes',
      authorized_key_types: ['ssh-ed25519', 'ecdsa-sha2-nistp256'],
      principal_policy: { min: 1, max: 5, regex: '^[a-z]+$' },
    });
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/templates');
    expect(body).toEqual({
      name: 'user-tpl',
      enabled: true,
      type: 'USER',
      lifetime: '30 days',
      backdate: '5 minutes',
      authorizedKeyTypes: ['ssh-ed25519', 'ecdsa-sha2-nistp256'],
      principalPolicy: { min: 1, max: 5, regex: '^[a-z]+$' },
    });
  });
});

describe('update_ssh_template', () => {
  it('GET-strip-merge-PUTs: strips id, PUTs collection root', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({
      id: 'tpl-id',
      name: 'sma',
      enabled: true,
      type: 'USER',
      lifetime: '30 days',
      principalPolicy: {},
    });
    let putPath: string | undefined;
    let putBody: any;
    client.put.mockImplementation(async (p: string, b: any) => {
      putPath = p;
      putBody = b;
      return { ...b };
    });
    await byName('update_ssh_template').h({ name: 'sma', enabled: false });
    expect(client.get).toHaveBeenCalledWith('/api/v1/ssh/templates/sma');
    expect(putPath).toBe('/api/v1/ssh/templates');
    expect(putBody.id).toBeUndefined();
    expect(putBody.enabled).toBe(false);
    expect(putBody.name).toBe('sma');
    expect(putBody.lifetime).toBe('30 days'); // preserved
  });
});

describe('delete_ssh_template', () => {
  it('deletes with matching echo and encodes the path', async () => {
    const { client, byName } = setup();
    client.delete.mockResolvedValue(null);
    await byName('delete_ssh_template').h({
      name: 'sma',
      expected_name: 'sma',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/ssh/templates/sma');
  });
});

// ---------------------------------------------------------------------------
// Certificates: search / aggregate / get
// ---------------------------------------------------------------------------

describe('search_ssh_certificates', () => {
  it('POSTs to /ssh/certificates/search, defaults empty query to `id exists`', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ results: [], pageIndex: 1, pageSize: 20 });
    await byName('search_ssh_certificates').h({});
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/certificates/search');
    expect(body.query).toBe('id exists');
    expect(body.pageIndex).toBe(1);
  });

  it('passes through a query, fields, and sortedBy', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ results: [] });
    await byName('search_ssh_certificates').h({
      query: 'type equals "USER"',
      fields: ['ca', 'serial', 'type'],
      sorted_by: 'validBefore:desc',
      page_index: 2,
      page_size: 10,
      with_count: true,
    });
    const body = client.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body.query).toBe('type equals "USER"');
    expect(body.fields).toEqual(['ca', 'serial', 'type']);
    // SortOrder is a case-sensitive PlayEnum: server expects "Desc", not "DESC".
    expect(body.sortedBy).toEqual([{ element: 'validBefore', order: 'Desc' }]);
    expect(body.pageIndex).toBe(2);
    expect(body.pageSize).toBe(10);
    expect(body.withCount).toBe(true);
  });

  it('emits the exact case-sensitive SortOrder entryName for each alias', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ results: [] });
    const cases: Array<[string, string]> = [
      ['validBefore:asc', 'Asc'],
      ['validBefore:DESC', 'Desc'],
      ['validBefore:KeyAsc', 'KeyAsc'],
      ['validBefore:keydesc', 'KeyDesc'],
      ['validBefore', 'Asc'], // default
    ];
    for (const [input, expectedOrder] of cases) {
      client.post.mockClear();
      await byName('search_ssh_certificates').h({ sorted_by: input });
      const body = client.post.mock.calls[0]![1] as Record<string, unknown>;
      expect(body.sortedBy).toEqual([
        { element: 'validBefore', order: expectedOrder },
      ]);
    }
  });
});

describe('aggregate_ssh_certificates', () => {
  it('POSTs groupBy + having + sortOrder + limit with camelCase', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ items: [], count: 0 });
    await byName('aggregate_ssh_certificates').h({
      query: 'status is expired',
      group_by: ['template'],
      with_count: true,
      sort_order: 'Desc',
      limit: 5,
      having_operator: 'gte',
      having_value: 1,
    });
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/certificates/aggregate');
    expect(body).toEqual({
      query: 'status is expired',
      groupBy: ['template'],
      withCount: true,
      sortOrder: 'Desc',
      limit: 5,
      having: { operator: 'gte', value: 1 },
    });
  });

  it('rejects a half-specified having clause', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('aggregate_ssh_certificates').h({ having_operator: 'gt' }),
    );
    expect(out).toContain('having_operator and having_value');
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('get_ssh_certificate', () => {
  it('rejects a non-ObjectId id without calling the client', async () => {
    const { client, byName } = setup();
    const out = await textOf(byName('get_ssh_certificate').h({ id: 'nope' }));
    expect(out).toContain('24-hex');
    expect(client.get).not.toHaveBeenCalled();
  });

  it('GETs /ssh/certificates/:id for a valid ObjectId', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({
      certificate: {},
      permissions: { revoke: true },
    });
    const id = '684be890674ec91198fbda3f';
    await byName('get_ssh_certificate').h({ id });
    expect(client.get).toHaveBeenCalledWith(`/api/v1/ssh/certificates/${id}`);
  });
});

// ---------------------------------------------------------------------------
// Lifecycle: enroll / revoke / list-requestable
// ---------------------------------------------------------------------------

describe('enroll_ssh_certificate', () => {
  it('POSTs publicKey + template{name} + principals (camelCase)', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ keyId: 'kid-1', serial: '12345' });
    await byName('enroll_ssh_certificate').h({
      ca: 'sma-rsa',
      public_key: 'ssh-ed25519 AAAA user@host',
      template: { name: 'user-tpl' },
      principals: ['alice'],
    });
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/lifecycle/enroll');
    expect(body).toEqual({
      ca: 'sma-rsa',
      publicKey: 'ssh-ed25519 AAAA user@host',
      template: { name: 'user-tpl' },
      principals: ['alice'],
    });
  });

  it('includes template overrides when supplied', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({});
    await byName('enroll_ssh_certificate').h({
      ca: 'sma-rsa',
      public_key: 'ssh-rsa AAAA',
      template: {
        name: 'user-tpl',
        type: 'USER',
        lifetime: '12 hours',
        backdate: '5 minutes',
      },
      principals: ['alice', 'bob'],
    });
    const body = client.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body.template).toEqual({
      name: 'user-tpl',
      type: 'USER',
      lifetime: '12 hours',
      backdate: '5 minutes',
    });
  });
});

describe('revoke_ssh_certificate', () => {
  it('Variant A: certificate present -> only certificate sent', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ keyId: 'kid', revoked: true });
    await byName('revoke_ssh_certificate').h({
      certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA',
      serial: '999',
      ca: 'ignored',
    });
    const [path, body] = client.post.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/lifecycle/revoke');
    expect(body).toEqual({
      certificate: 'ssh-ed25519-cert-v01@openssh.com AAAA',
    });
  });

  it('Variant B: serial + ca', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ revoked: true });
    await byName('revoke_ssh_certificate').h({
      serial: '12345',
      ca: 'sma-rsa',
    });
    const body = client.post.mock.calls[0]![1] as Record<string, unknown>;
    expect(body).toEqual({ serial: '12345', ca: 'sma-rsa' });
  });

  it('rejects when neither certificate nor serial+ca is provided', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('revoke_ssh_certificate').h({ ca: 'sma-rsa' }),
    );
    expect(out).toContain('serial');
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('list_requestable_ssh_templates', () => {
  it('GETs /ssh/lifecycle/templates with no params by default', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    await byName('list_requestable_ssh_templates').h({});
    expect(client.getList).toHaveBeenCalledWith(
      '/api/v1/ssh/lifecycle/templates',
      undefined,
    );
  });

  it('passes the permission query param', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    await byName('list_requestable_ssh_templates').h({ permission: 'enroll' });
    const [path, params] = client.getList.mock.calls[0]!;
    expect(path).toBe('/api/v1/ssh/lifecycle/templates');
    expect((params as URLSearchParams).toString()).toBe('permission=enroll');
  });
});
