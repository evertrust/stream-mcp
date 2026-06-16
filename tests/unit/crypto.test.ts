import { describe, expect, it, vi } from 'vitest';

import type { StreamClient } from '../../src/client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { registerCryptoTools } from '../../src/tools/crypto/index.js';

// --- harness ---------------------------------------------------------------

interface Captured {
  n: string;
  c: any;
  h: (...args: any[]) => any;
}

function setup() {
  const calls: Captured[] = [];
  const server = {
    registerTool: (n: string, c: any, h: any) => calls.push({ n, c, h }),
  } as unknown as McpServer;
  const client = {
    get: vi.fn(),
    getList: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    getText: vi.fn(),
    postMultipart: vi.fn(),
  } as unknown as StreamClient & Record<string, ReturnType<typeof vi.fn>>;
  registerCryptoTools(server, client);
  const tool = (name: string) => {
    const c = calls.find((x) => x.n === name);
    if (!c) throw new Error(`tool not registered: ${name}`);
    return c;
  };
  const invoke = (name: string, args: any) => tool(name).h(args, {} as any);
  return { calls, server, client, tool, invoke };
}

const parse = (res: any) => JSON.parse(res.content[0].text);

const EXPECTED_TOOLS = [
  'list_keystores',
  'get_keystore',
  'create_keystore',
  'update_keystore',
  'delete_keystore',
  'list_keys',
  'get_key',
  'create_key',
  'delete_key',
  'find_ca_keys',
  'get_hsm_info',
  'get_hsm_slots',
];

// --- registration ----------------------------------------------------------

describe('registerCryptoTools registration', () => {
  it('registers exactly the 12 crypto tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual([...EXPECTED_TOOLS].sort());
    expect(names.length).toBe(12);
  });
});

// --- keystores -------------------------------------------------------------

describe('list_keystores', () => {
  it('GETs the keystore collection via getList (204 -> [])', async () => {
    const { client, invoke } = setup();
    (client.getList as any).mockResolvedValue([
      { name: 'A', type: 'software' },
    ]);
    const res = await invoke('list_keystores', { max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/crypto/keystores');
    expect(parse(res).items).toHaveLength(1);
  });
});

describe('get_keystore', () => {
  it('GETs a single keystore by encoded name', async () => {
    const { client, invoke } = setup();
    (client.get as any).mockResolvedValue({ name: 'My KS' });
    await invoke('get_keystore', { name: 'My KS' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/crypto/keystores/My%20KS');
  });
});

describe('create_keystore', () => {
  it('software: posts type + name + description only', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ id: 'x', name: 'soft' });
    await invoke('create_keystore', {
      type: 'software',
      name: 'soft',
      description: 'desc',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keystores', {
      type: 'software',
      name: 'soft',
      description: 'desc',
    });
  });

  it('pkcs11: maps snake_case to camelCase and wraps pin as {clear}', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ id: 'x', name: 'hsm' });
    await invoke('create_keystore', {
      type: 'pkcs11',
      name: 'hsm',
      library: '/lib.so',
      slot: 42,
      rsa_x931_mode: false,
      pool_size: 4,
      user_type: 1,
      pin: 's3cret',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keystores', {
      type: 'pkcs11',
      name: 'hsm',
      library: '/lib.so',
      slot: 42,
      rsaX931Mode: false,
      poolSize: 4,
      userType: 1,
      pin: { clear: 's3cret' },
    });
  });

  it('pkcs11: missing required fields -> isError (no POST)', async () => {
    const { client, invoke } = setup();
    const res = await invoke('create_keystore', {
      type: 'pkcs11',
      name: 'hsm',
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('library');
    expect(client.post).not.toHaveBeenCalled();
  });

  it('aws: maps role_arn -> roleArn and keeps credentials reference', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ id: 'x', name: 'aws' });
    await invoke('create_keystore', {
      type: 'aws',
      name: 'aws',
      region: 'us-east-1',
      credentials: 'AWS',
      role_arn: 'arn:aws:iam::1:role/r',
      timeout: '5 seconds',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keystores', {
      type: 'aws',
      name: 'aws',
      region: 'us-east-1',
      credentials: 'AWS',
      roleArn: 'arn:aws:iam::1:role/r',
      timeout: '5 seconds',
    });
  });

  it('akv: requires vault_url and maps to vaultUrl', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ id: 'x', name: 'akv' });
    await invoke('create_keystore', {
      type: 'akv',
      name: 'akv',
      vault_url: 'https://v.vault.azure.net/',
      tenant: 't',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keystores', {
      type: 'akv',
      name: 'akv',
      vaultUrl: 'https://v.vault.azure.net/',
      tenant: 't',
    });
  });

  it('akv: missing vault_url -> isError', async () => {
    const { client, invoke } = setup();
    const res = await invoke('create_keystore', { type: 'akv', name: 'akv' });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('vault_url');
    expect(client.post).not.toHaveBeenCalled();
  });

  it('gcp: maps key_ring -> keyRing and requires project/location/key_ring', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ id: 'x', name: 'gcp' });
    await invoke('create_keystore', {
      type: 'gcp',
      name: 'gcp',
      project: 'p',
      location: 'global',
      key_ring: 'ring',
      credentials: 'GCP',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keystores', {
      type: 'gcp',
      name: 'gcp',
      project: 'p',
      location: 'global',
      keyRing: 'ring',
      credentials: 'GCP',
    });
  });
});

describe('update_keystore', () => {
  it('GET-strip(id,status,pin)-merge-PUT on the collection root', async () => {
    const { client, invoke } = setup();
    (client.get as any).mockResolvedValue({
      id: 'srv-id',
      type: 'pkcs11',
      name: 'hsm',
      library: '/old.so',
      slot: 1,
      rsaX931Mode: false,
      pin: {}, // sanitized on read — must NOT be re-sent
      status: { status: 'failure' },
    });
    (client.put as any).mockImplementation(async (_p: string, b: any) => b);
    await invoke('update_keystore', {
      type: 'pkcs11',
      name: 'hsm',
      library: '/new.so',
      slot: 2,
      rsa_x931_mode: true,
    });
    const [putPath, putBody] = (client.put as any).mock.calls[0];
    expect(client.get).toHaveBeenCalledWith('/api/v1/crypto/keystores/hsm');
    expect(putPath).toBe('/api/v1/crypto/keystores'); // collection root
    // server fields stripped
    expect(putBody.id).toBeUndefined();
    expect(putBody.status).toBeUndefined();
    // pin omitted when not supplied (retained server-side)
    expect(putBody.pin).toBeUndefined();
    // overrides applied (camelCase)
    expect(putBody).toMatchObject({
      type: 'pkcs11',
      name: 'hsm',
      library: '/new.so',
      slot: 2,
      rsaX931Mode: true,
    });
  });

  it('pkcs11: supplying pin re-sends it as {clear}', async () => {
    const { client, invoke } = setup();
    (client.get as any).mockResolvedValue({
      id: 'srv',
      type: 'pkcs11',
      name: 'hsm',
      library: '/old.so',
      slot: 1,
      rsaX931Mode: false,
      pin: {},
    });
    (client.put as any).mockImplementation(async (_p: string, b: any) => b);
    await invoke('update_keystore', {
      type: 'pkcs11',
      name: 'hsm',
      library: '/old.so',
      slot: 1,
      rsa_x931_mode: false,
      pin: 'rotated',
    });
    const [, putBody] = (client.put as any).mock.calls[0];
    expect(putBody.pin).toEqual({ clear: 'rotated' });
  });
});

describe('delete_keystore', () => {
  it('deletes by encoded name when the echo guard matches', async () => {
    const { client, invoke } = setup();
    (client.delete as any).mockResolvedValue(null);
    const res = await invoke('delete_keystore', {
      name: 'ks',
      expected_name: 'ks',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/crypto/keystores/ks');
    expect(parse(res)).toEqual({ deleted: true, name: 'ks', kind: 'keystore' });
  });

  it('rejects mismatched echo guard (isError, no delete)', async () => {
    const { client, invoke } = setup();
    const res = await invoke('delete_keystore', {
      name: 'ks',
      expected_name: 'WRONG',
    });
    expect(res.isError).toBe(true);
    expect(client.delete).not.toHaveBeenCalled();
  });

  it('has the destructive annotation', () => {
    const { tool } = setup();
    expect(tool('delete_keystore').c.annotations.destructiveHint).toBe(true);
  });
});

// --- keys ------------------------------------------------------------------

describe('list_keys', () => {
  it('GETs /crypto/keys/:keystore with unusedOnly query', async () => {
    const { client, invoke } = setup();
    (client.getList as any).mockResolvedValue([{ name: 'k1' }]);
    await invoke('list_keys', {
      keystore: 'PQC',
      unused_only: true,
      max_items: 50,
    });
    const [path, params] = (client.getList as any).mock.calls[0];
    expect(path).toBe('/api/v1/crypto/keys/PQC');
    expect(params.get('unusedOnly')).toBe('true');
  });

  it('omits the query string when unused_only is not provided', async () => {
    const { client, invoke } = setup();
    (client.getList as any).mockResolvedValue([]);
    await invoke('list_keys', { keystore: 'PQC', max_items: 50 });
    const [path, params] = (client.getList as any).mock.calls[0];
    expect(path).toBe('/api/v1/crypto/keys/PQC');
    expect(params).toBeUndefined();
  });
});

describe('get_key', () => {
  it('GETs /crypto/keys/:keystore/:key (both segments encoded)', async () => {
    const { client, invoke } = setup();
    (client.get as any).mockResolvedValue({ name: 'k' });
    await invoke('get_key', { keystore: 'AWS', key: 'arn:aws:kms:k/1' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/crypto/keys/AWS/arn%3Aaws%3Akms%3Ak%2F1',
    );
  });
});

describe('create_key', () => {
  it('POSTs to /crypto/keys with keystore in body and algorithm as description', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue({ name: 'k', keystore: 'soft' });
    await invoke('create_key', {
      name: 'k',
      keystore: 'soft',
      algorithm: 'rsa-2048',
      extractable: true,
      hardware_protected: false,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keys', {
      name: 'k',
      keystore: 'soft',
      description: 'rsa-2048',
      extractable: true,
      hardwareProtected: false,
    });
  });

  it('warns when GCP returns 204 (null result, key not yet readable)', async () => {
    const { client, invoke } = setup();
    (client.post as any).mockResolvedValue(null);
    const res = await invoke('create_key', {
      name: 'k',
      keystore: 'gcp',
      algorithm: 'rsa-2048',
    });
    expect(parse(res).warnings[0]).toContain('not yet readable');
  });
});

describe('delete_key', () => {
  it('deletes /crypto/keys/:keystore/:key when echo guard matches', async () => {
    const { client, invoke } = setup();
    (client.delete as any).mockResolvedValue(null);
    const res = await invoke('delete_key', {
      keystore: 'soft',
      key: '8888',
      expected_key: '8888',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/crypto/keys/soft/8888');
    expect(parse(res)).toEqual({
      deleted: true,
      keystore: 'soft',
      key: '8888',
      kind: 'key',
    });
  });

  it('rejects mismatched echo guard (isError, no delete)', async () => {
    const { client, invoke } = setup();
    const res = await invoke('delete_key', {
      keystore: 'soft',
      key: '8888',
      expected_key: 'nope',
    });
    expect(res.isError).toBe(true);
    expect(client.delete).not.toHaveBeenCalled();
  });
});

describe('find_ca_keys', () => {
  it('POSTs ca PEM + unusedOnly to /crypto/keys/:keystore and is read-only', async () => {
    const { client, invoke, tool } = setup();
    (client.post as any).mockResolvedValue([{ name: 'match' }]);
    await invoke('find_ca_keys', {
      keystore: 'PQC',
      ca: '-----BEGIN CERTIFICATE-----\\nAAA\\n-----END CERTIFICATE-----',
      unused_only: true,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/crypto/keys/PQC', {
      ca: '-----BEGIN CERTIFICATE-----\\nAAA\\n-----END CERTIFICATE-----',
      unusedOnly: true,
    });
    expect(tool('find_ca_keys').c.annotations.readOnlyHint).toBe(true);
  });
});

describe('hsm', () => {
  it('get_hsm_info GETs /crypto/hsms/:library (encoded path)', async () => {
    const { client, invoke } = setup();
    (client.get as any).mockResolvedValue({ libraryVersion: '2.06' });
    await invoke('get_hsm_info', {
      library: '/usr/lib/softhsm/libsofthsm2.so',
    });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/crypto/hsms/%2Fusr%2Flib%2Fsofthsm%2Flibsofthsm2.so',
    );
  });

  it('get_hsm_slots GETs /crypto/hsms/:library/slots via getList', async () => {
    const { client, invoke } = setup();
    (client.getList as any).mockResolvedValue([{ id: 1 }]);
    await invoke('get_hsm_slots', { library: '/lib.so' });
    expect(client.getList).toHaveBeenCalledWith(
      '/api/v1/crypto/hsms/%2Flib.so/slots',
    );
  });
});
