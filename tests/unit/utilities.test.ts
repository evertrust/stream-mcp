import { describe, expect, it, vi } from 'vitest';

import { registerUtilityTools } from '../../src/tools/utilities/index.js';

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
  } as any;
  registerUtilityTools(server, client);
  return { tools, client };
}

function tool(tools: RegisteredTool[], name: string): RegisteredTool {
  const t = tools.find((x) => x.name === name);
  if (!t) throw new Error(`tool not registered: ${name}`);
  return t;
}

function payload(result: any): any {
  return result.content[0].text;
}
function json(result: any): any {
  return JSON.parse(payload(result));
}

// Pull the single multipart part with a given field name out of the parts array.
function part(parts: any[], fieldName: string): any {
  return parts.find((p) => p.fieldName === fieldName);
}

const ALL_TOOLS = [
  'detect_file',
  'decode_x509',
  'decode_crl',
  'decode_csr',
  'extract_pkcs12',
  'get_trust_chain',
  'decode_openssh_pubkey',
  'list_trust_chains',
  'get_trust_chain_for_anchor',
  'list_ekus',
  'get_eku',
  'create_eku',
  'update_eku',
  'delete_eku',
];

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe('registerUtilityTools — registration', () => {
  it('registers exactly the 14 expected tools', () => {
    const { tools } = setup();
    const names = tools.map((t) => t.name).sort();
    expect(names).toEqual([...ALL_TOOLS].sort());
    expect(names).toHaveLength(14);
  });
});

// ---------------------------------------------------------------------------
// Decoders — exact multipart field names + Accept application/json
// ---------------------------------------------------------------------------

describe('decoders', () => {
  it('detect_file POSTs multipart with field "file" + Accept application/json', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({ type: 'certificate', value: {} });
    const res = await tool(tools, 'detect_file').handler({
      content: 'PEMDATA',
    });
    const [path, parts, accept] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/detect');
    expect(part(parts, 'file')).toBeDefined();
    expect(part(parts, 'file').data).toBe('PEMDATA');
    expect(part(parts, 'file').mimeType).toBe('application/octet-stream');
    expect(accept).toBe('application/json');
    expect(json(res).type).toBe('certificate');
  });

  it('decode_x509 POSTs multipart with field "x509"', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({ dn: 'CN=x' });
    await tool(tools, 'decode_x509').handler({ content: 'CERTPEM' });
    const [path, parts, accept] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/x509');
    expect(part(parts, 'x509').data).toBe('CERTPEM');
    expect(accept).toBe('application/json');
  });

  it('decode_crl POSTs multipart with field "crl"', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({ issuerDn: 'CN=ca' });
    await tool(tools, 'decode_crl').handler({ content: 'CRLPEM' });
    const [path, parts] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/crl');
    expect(part(parts, 'crl').data).toBe('CRLPEM');
  });

  it('decode_csr POSTs multipart with field "pkcs10"', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({ dn: 'CN=req' });
    await tool(tools, 'decode_csr').handler({ content: 'CSRPEM' });
    const [path, parts] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/pkcs10');
    expect(part(parts, 'pkcs10').data).toBe('CSRPEM');
  });

  it('extract_pkcs12 POSTs multipart with file "pkcs12" + text part "password"', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({
      certificate: { dn: 'CN=x' },
      privateKey: '-----BEGIN PRIVATE KEY-----...',
    });
    await tool(tools, 'extract_pkcs12').handler({
      content: 'P12BASE64',
      password: 's3cret',
    });
    const [path, parts] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/pkcs12');
    expect(part(parts, 'pkcs12').data).toBe('P12BASE64');
    const pw = part(parts, 'password');
    expect(pw).toBeDefined();
    expect(pw.data).toBe('s3cret');
    expect(pw.mimeType).toBe('text/plain');
  });

  it('decode_openssh_pubkey POSTs multipart with field "sshPublicKey"', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue({ keyType: 'ssh-ed25519' });
    await tool(tools, 'decode_openssh_pubkey').handler({
      content: 'ssh-ed25519 AAAA...',
    });
    const [path, parts] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/openssh/pubkey');
    expect(part(parts, 'sshPublicKey').data).toBe('ssh-ed25519 AAAA...');
  });
});

// ---------------------------------------------------------------------------
// Trust chains
// ---------------------------------------------------------------------------

describe('trust chains', () => {
  it('get_trust_chain reuses the x509 field and omits order when unset', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue([{ dn: 'CN=leaf' }]);
    await tool(tools, 'get_trust_chain').handler({ content: 'LEAFPEM' });
    const [path, parts, accept] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/tc');
    expect(part(parts, 'x509').data).toBe('LEAFPEM');
    expect(accept).toBe('application/json');
  });

  it('get_trust_chain appends ?order= when provided', async () => {
    const { tools, client } = setup();
    client.postMultipart.mockResolvedValue([]);
    await tool(tools, 'get_trust_chain').handler({
      content: 'LEAFPEM',
      order: 'rtl',
    });
    const [path] = client.postMultipart.mock.calls[0];
    expect(path).toBe('/api/v1/rfc5280/tc?order=rtl');
  });

  it('list_trust_chains uses getList on /trustchains (204 -> [])', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([
      { ca: { name: 'root-1' }, subordinates: [] },
      { ca: { name: 'root-2' }, subordinates: [] },
    ]);
    const res = await tool(tools, 'list_trust_chains').handler({
      max_items: 100,
    });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/trustchains');
    expect(json(res).items).toHaveLength(2);
    expect(json(res).kind).toBe('trust_chain');
  });

  it('get_trust_chain_for_anchor GETs /trustchains/:anchor (name, encoded)', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({ ca: { name: 'My CA' }, subordinates: [] });
    await tool(tools, 'get_trust_chain_for_anchor').handler({
      anchor: 'My CA',
    });
    expect(client.get).toHaveBeenCalledWith('/api/v1/trustchains/My%20CA');
  });
});

// ---------------------------------------------------------------------------
// EKUs
// ---------------------------------------------------------------------------

describe('ekus', () => {
  it('list_ekus uses getList on the collection root', async () => {
    const { tools, client } = setup();
    client.getList.mockResolvedValue([
      { name: 'serverAuth', oid: '1.3.6.1.5.5.7.3.1', custom: false },
    ]);
    const res = await tool(tools, 'list_ekus').handler({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/extension/ekus');
    expect(json(res).items).toHaveLength(1);
  });

  it('get_eku reads by :oid path segment (encoded)', async () => {
    const { tools, client } = setup();
    client.get.mockResolvedValue({
      name: 'serverAuth',
      oid: '1.3.6.1.5.5.7.3.1',
      custom: false,
    });
    await tool(tools, 'get_eku').handler({ oid: '1.3.6.1.5.5.7.3.1' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/extension/ekus/1.3.6.1.5.5.7.3.1',
    );
  });

  it('create_eku POSTs flat { name, oid } (custom is server-controlled)', async () => {
    const { tools, client } = setup();
    client.post.mockResolvedValue({
      name: 'myEku',
      oid: '1.3.4',
      custom: true,
    });
    const res = await tool(tools, 'create_eku').handler({
      name: 'myEku',
      oid: '1.3.4',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/extension/ekus', {
      name: 'myEku',
      oid: '1.3.4',
    });
    // never sends custom on the wire
    expect(client.post.mock.calls[0][1]).not.toHaveProperty('custom');
    expect(json(res).status).toBe('created');
    expect(json(res).name).toBe('1.3.4');
  });

  it('create_eku rejects a malformed OID before the round-trip', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'create_eku').handler({
      name: 'myEku',
      oid: 'not-an-oid',
    });
    expect(client.post).not.toHaveBeenCalled();
    expect(json(res).error).toBe('INVALID_OID');
  });

  it('update_eku PUTs flat { oid, name } on the collection root (no GET, no path param)', async () => {
    const { tools, client } = setup();
    client.put.mockResolvedValue({
      name: 'renamed',
      oid: '1.3.4',
      custom: true,
    });
    const res = await tool(tools, 'update_eku').handler({
      oid: '1.3.4',
      name: 'renamed',
    });
    expect(client.get).not.toHaveBeenCalled();
    expect(client.put).toHaveBeenCalledWith('/api/v1/extension/ekus', {
      oid: '1.3.4',
      name: 'renamed',
    });
    expect(json(res).status).toBe('updated');
    expect(json(res).name).toBe('1.3.4');
  });

  it('delete_eku enforces the expected_oid echo guard', async () => {
    const { tools, client } = setup();
    const res = await tool(tools, 'delete_eku').handler({
      oid: '1.3.4',
      expected_oid: '9.9.9',
    });
    expect(client.delete).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
  });

  it('delete_eku proceeds when expected_oid matches', async () => {
    const { tools, client } = setup();
    client.delete.mockResolvedValue(null);
    await tool(tools, 'delete_eku').handler({
      oid: '1.3.4',
      expected_oid: '1.3.4',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/extension/ekus/1.3.4');
  });
});
