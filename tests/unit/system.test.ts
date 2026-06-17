import { describe, expect, it, vi } from 'vitest';

import { registerSystemTools } from '../../src/tools/system/index.js';

// ---------------------------------------------------------------------------
// Harness: mock MCP server + mock StreamClient.
// registerTool() (foundation) calls server.registerTool(name, config, handler).
// ---------------------------------------------------------------------------

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
    exportTimeout: 120000,
  } as any;
  registerSystemTools(server, client);
  return { tools, client };
}

function tool(tools: RegisteredTool[], name: string): RegisteredTool {
  const t = tools.find((x) => x.name === name);
  if (!t) throw new Error(`tool not registered: ${name}`);
  return t;
}

// Parse the single text content payload back to JSON (or raw string).
function payload(result: any): any {
  return result.content[0].text;
}
function json(result: any): any {
  return JSON.parse(payload(result));
}

const ALL_TOOLS = [
  'list_system_configuration',
  'get_system_configuration',
  'upsert_system_configuration',
  'list_proxies',
  'get_proxy',
  'create_proxy',
  'update_proxy',
  'delete_proxy',
  'list_queues',
  'get_queue',
  'create_queue',
  'update_queue',
  'delete_queue',
  'get_license_info',
  'get_license_modules',
  'get_key_types',
  'get_dn_elements',
  'get_san_types',
  'export_configuration',
];

describe('registerSystemTools — registration', () => {
  it('registers exactly the 19 expected tools', () => {
    const { tools } = setup();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...ALL_TOOLS].sort());
    expect(names).toHaveLength(19);
  });
});

// ---------------------------------------------------------------------------
// System configuration (keyed by type)
// ---------------------------------------------------------------------------

describe('system configuration', () => {
  it('list uses getList on the collection root', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([
      { id: '1', type: 'internal_monitor', cron: '0 * * ? * * ' },
      { id: '2', type: 'license' },
    ]);
    const res = await tool(tools, 'list_system_configuration').handler({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/system/configuration');
    expect(json(res).items).toHaveLength(2);
  });

  it('get reads by :type path segment', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({ id: '2', type: 'license' });
    await tool(tools, 'get_system_configuration').handler({ type: 'license' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/system/configuration/license',
    );
  });

  it('upsert license maps triggers.onLicenseExpiration and PUTs on collection root', async () => {
    const { tools, client } = setup();
    client.put.mockResolvedValue({ id: '2', type: 'license' });
    await tool(tools, 'upsert_system_configuration').handler({
      config: { type: 'license', on_license_expiration: ['notify-admins'] },
    });
    expect(client.put).toHaveBeenCalledWith('/api/v1/system/configuration', {
      type: 'license',
      triggers: { onLicenseExpiration: ['notify-admins'] },
    });
  });

  it('upsert license without triggers omits the triggers object', async () => {
    const { tools, client } = setup();
    client.put.mockResolvedValue({ id: '2', type: 'license' });
    await tool(tools, 'upsert_system_configuration').handler({
      config: { type: 'license' },
    });
    expect(client.put).toHaveBeenCalledWith('/api/v1/system/configuration', {
      type: 'license',
    });
  });

  it('upsert internal_monitor sends cron', async () => {
    const { tools, client } = setup();
    client.put.mockResolvedValue({ id: '1', type: 'internal_monitor' });
    const res = await tool(tools, 'upsert_system_configuration').handler({
      config: { type: 'internal_monitor', cron: '0 0 0 ? * * *' },
    });
    expect(client.put).toHaveBeenCalledWith('/api/v1/system/configuration', {
      type: 'internal_monitor',
      cron: '0 0 0 ? * * *',
    });
    expect(json(res).status).toBe('upserted');
    expect(json(res).name).toBe('internal_monitor');
  });
});

// ---------------------------------------------------------------------------
// Proxies
// ---------------------------------------------------------------------------

describe('proxies', () => {
  it('list uses getList on /system/proxies', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([{ name: 'p', host: 'a.b', port: 1 }]);
    await tool(tools, 'list_proxies').handler({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/system/proxies');
  });

  it('get encodes the name into the item path', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({ name: 'p', host: 'a.b', port: 1 });
    await tool(tools, 'get_proxy').handler({ name: 'p' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/system/proxies/p');
  });

  it('create POSTs name/host/port', async () => {
    const { tools, client } = setup();
    client.post.mockResolvedValue({
      name: 'corp',
      host: 'proxy.corp.com',
      port: 8080,
    });
    await tool(tools, 'create_proxy').handler({
      name: 'corp',
      host: 'proxy.corp.com',
      port: 8080,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/system/proxies', {
      name: 'corp',
      host: 'proxy.corp.com',
      port: 8080,
    });
  });

  it('create rejects an invalid host (no dot) before calling the API', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'create_proxy').handler({
      name: 'corp',
      host: 'nodothost',
      port: 8080,
    });
    expect(client.post).not.toHaveBeenCalled();
    expect(json(res).error).toBe('INVALID_HOST');
  });

  it('create accepts an IPv4 host', async () => {
    const { tools, client } = setup();
    client.post.mockResolvedValue({});
    await tool(tools, 'create_proxy').handler({
      name: 'corp',
      host: '10.0.0.1',
      port: 3128,
    });
    expect(client.post).toHaveBeenCalled();
  });

  it('update strips id (GET-strip-merge-PUT) and PUTs on collection root', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'corp',
      host: 'old.host.com',
      port: 1,
    });
    let putBody: any;
    client.put.mockImplementation(async (_p: string, b: any) => {
      putBody = b;
      return { ...b, id: 'srv-id' };
    });
    await tool(tools, 'update_proxy').handler({ name: 'corp', port: 8888 });
    // GET on item path, PUT on collection root
    expect(client.get).toHaveBeenCalledWith('/api/v1/system/proxies/corp');
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/system/proxies');
    // id stripped, name + host preserved, port overridden
    expect(putBody).toEqual({ name: 'corp', host: 'old.host.com', port: 8888 });
    expect(putBody.id).toBeUndefined();
  });

  it('delete enforces the expected_name echo guard', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'delete_proxy').handler({
      name: 'corp',
      expected_name: 'wrong',
    });
    expect(client.delete).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
  });

  it('delete proceeds when expected_name matches', async () => {
    const { tools, client } = setup();
    client.delete.mockResolvedValue(null);
    await tool(tools, 'delete_proxy').handler({
      name: 'corp',
      expected_name: 'corp',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/system/proxies/corp');
  });
});

// ---------------------------------------------------------------------------
// Queues
// ---------------------------------------------------------------------------

describe('queues', () => {
  it('list uses getList on /queues', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([]);
    await tool(tools, 'list_queues').handler({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/queues');
  });

  it('create maps snake_case to camelCase wire fields', async () => {
    const { tools, client } = setup();
    client.post.mockResolvedValue({});
    await tool(tools, 'create_queue').handler({
      name: 'issuance',
      description: 'CA issuance queue',
      size: 10,
      throttle_duration: '1 second',
      throttle_parallelism: 5,
      cluster_wide: true,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/queues', {
      name: 'issuance',
      size: 10,
      clusterWide: true,
      description: 'CA issuance queue',
      throttleDuration: '1 second',
      throttleParallelism: 5,
    });
  });

  it('create omits unset optional fields', async () => {
    const { tools, client } = setup();
    client.post.mockResolvedValue({});
    await tool(tools, 'create_queue').handler({
      name: 'sma',
      size: 1,
      cluster_wide: false,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/queues', {
      name: 'sma',
      size: 1,
      clusterWide: false,
    });
  });

  it('create rejects throttle_duration without throttle_parallelism', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'create_queue').handler({
      name: 'q',
      size: 1,
      cluster_wide: false,
      throttle_duration: '1 second',
    });
    expect(client.post).not.toHaveBeenCalled();
    expect(json(res).error).toBe('THROTTLE_PARALLELISM_REQUIRED');
  });

  it('create rejects a malformed throttle_duration', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'create_queue').handler({
      name: 'q',
      size: 1,
      cluster_wide: false,
      throttle_duration: 'fortnight',
      throttle_parallelism: 5,
    });
    expect(client.post).not.toHaveBeenCalled();
    expect(json(res).error).toBe('INVALID_THROTTLE_DURATION');
  });

  it('update maps camelCase overrides and strips id on PUT to collection root', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({
      id: 'qid',
      name: 'test',
      size: 2,
      throttleParallelism: 5,
      clusterWide: false,
    });
    let putBody: any;
    client.put.mockImplementation(async (_p: string, b: any) => {
      putBody = b;
      return b;
    });
    await tool(tools, 'update_queue').handler({ name: 'test', size: 9 });
    expect(client.get).toHaveBeenCalledWith('/api/v1/queues/test');
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/queues');
    expect(putBody).toEqual({
      name: 'test',
      size: 9,
      throttleParallelism: 5,
      clusterWide: false,
    });
    expect(putBody.id).toBeUndefined();
  });

  it('delete enforces the echo guard', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'delete_queue').handler({
      name: 'test',
      expected_name: 'nope',
    });
    expect(client.delete).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// License / dictionaries / export
// ---------------------------------------------------------------------------

describe('license, dictionaries, export', () => {
  it('get_license_info GETs /licenses', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({ isValid: true, version: '2.1.9' });
    await tool(tools, 'get_license_info').handler({});
    expect(client.get).toHaveBeenCalledWith('/api/v1/licenses');
  });

  it('get_license_modules getLists /licenses/modules', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue(['stream-ca', 'stream-va']);
    const res = await tool(tools, 'get_license_modules').handler({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/licenses/modules');
    expect(json(res).modules).toEqual(['stream-ca', 'stream-va']);
    expect(json(res).count).toBe(2);
  });

  it('get_key_types getLists /dictionaries/keys', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([
      { name: 'rsa-2048', pqc: false, type: 'RSA' },
    ]);
    await tool(tools, 'get_key_types').handler({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/dictionaries/keys');
  });

  it('get_dn_elements getLists /dictionaries/dns', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue(['CN', 'OU']);
    await tool(tools, 'get_dn_elements').handler({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/dictionaries/dns');
  });

  it('get_san_types getLists /dictionaries/sans', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue(['DNSNAME']);
    await tool(tools, 'get_san_types').handler({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/dictionaries/sans');
  });

  it('export_configuration uses getText with text/plain accept (no trust chains by default)', async () => {
    const { tools, client } = setup();
    client.getText.mockResolvedValue('= Stream Configuration Cookbook');
    const res = await tool(tools, 'export_configuration').handler({});
    // Exports use the longer exportTimeout, not the default request timeout.
    expect(client.getText).toHaveBeenCalledWith(
      '/api/v1/adoc',
      'text/plain',
      120000,
    );
    expect(payload(res)).toContain('Cookbook');
  });

  it('export_configuration adds ?withTrustChains=true when requested', async () => {
    const { tools, client } = setup();
    client.getText.mockResolvedValue('= ...');
    await tool(tools, 'export_configuration').handler({
      with_trust_chains: true,
    });
    expect(client.getText).toHaveBeenCalledWith(
      '/api/v1/adoc?withTrustChains=true',
      'text/plain',
      120000,
    );
  });
});
