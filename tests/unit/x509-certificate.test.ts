import { describe, expect, it, vi } from 'vitest';

import { registerX509CertificateTools } from '../../src/tools/x509-certificate/index.js';

type Captured = { n: string; c: any; h: any };

function setup() {
  const calls: Captured[] = [];
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
  } as any;
  registerX509CertificateTools(server, client);
  const tool = (name: string) => {
    const c = calls.find((x) => x.n === name);
    if (!c) throw new Error(`tool ${name} not registered`);
    return c;
  };
  return { calls, server, client, tool };
}

const lastText = (res: any): string => res.content[0].text;

describe('x509-certificate registration', () => {
  it('registers exactly the 6 domain tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual(
      [
        'aggregate_certificates',
        'enroll_certificate',
        'get_certificate',
        'list_requestable_templates',
        'revoke_certificate',
        'search_certificates',
      ].sort(),
    );
  });
});

describe('search_certificates', () => {
  it('defaults empty query to `id exists` and posts the search payload', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({
      results: [{ id: 'a' }],
      pageIndex: 1,
      pageSize: 20,
      hasMore: false,
    });
    const res = await tool('search_certificates').h({});
    expect(client.post).toHaveBeenCalledWith('/api/v1/certificates/search', {
      query: 'id exists',
      pageIndex: 1,
      pageSize: 20,
    });
    const body = JSON.parse(lastText(res));
    expect(body.results).toEqual([{ id: 'a' }]);
    expect(body.page_index).toBe(1);
    expect(res.structuredContent.page_index).toBe(1);
  });

  it('passes through query, fields, paging, sort, count', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ results: [], count: 0 });
    await tool('search_certificates').h({
      query: 'status is valid',
      fields: ['id', 'dn', 'serial'],
      page_index: 2,
      page_size: 50,
      sorted_by: 'notAfter:desc',
      with_count: true,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/certificates/search', {
      query: 'status is valid',
      pageIndex: 2,
      pageSize: 50,
      fields: ['id', 'dn', 'serial'],
      sortedBy: [{ element: 'notAfter', order: 'Desc' }],
      withCount: true,
    });
  });
});

describe('aggregate_certificates', () => {
  it('defaults query to `id exists` and maps groupBy + count', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({
      items: [{ _id: { status: 'valid' }, count: 3 }],
    });
    await tool('aggregate_certificates').h({
      group_by: ['status'],
      with_count: true,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/certificates/aggregate', {
      query: 'id exists',
      groupBy: ['status'],
      withCount: true,
    });
  });

  it('maps sort_order, limit and having into the wire body', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ items: [] });
    await tool('aggregate_certificates').h({
      query: 'template exists',
      group_by: ['template'],
      sort_order: 'Desc',
      limit: 5,
      having_operator: 'gte',
      having_value: 10,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/certificates/aggregate', {
      query: 'template exists',
      groupBy: ['template'],
      sortOrder: 'Desc',
      limit: 5,
      having: { operator: 'gte', value: 10 },
    });
  });

  it('errors when only one of having_operator/having_value is given', async () => {
    const { client, tool } = setup();
    const res = await tool('aggregate_certificates').h({
      having_operator: 'gt',
    });
    expect(res.isError).toBe(true);
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('get_certificate', () => {
  it('GETs the certificate by id', async () => {
    const { client, tool } = setup();
    const id = '68ef68b13b69f44269cb7288';
    client.get.mockResolvedValue({
      certificate: { id },
      permissions: { revoke: false },
    });
    const res = await tool('get_certificate').h({ id });
    expect(client.get).toHaveBeenCalledWith(`/api/v1/certificates/${id}`);
    expect(JSON.parse(lastText(res)).certificate.id).toBe(id);
  });

  it('rejects a malformed id before hitting the network', async () => {
    const { client, tool } = setup();
    const res = await tool('get_certificate').h({ id: 'not-an-objectid' });
    expect(res.isError).toBe(true);
    expect(client.get).not.toHaveBeenCalled();
  });
});

describe('enroll_certificate', () => {
  it('builds the enroll payload with camelCase template overrides', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ id: 'new', dn: 'CN=test' });
    await tool('enroll_certificate').h({
      ca: 'ISSUING_CA',
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----',
      template_name: 'ServerCert',
      dn: 'CN=test',
      template_overrides: {
        path_len: 0,
        lifetime: '365 days',
        backdate: '1 hour',
        check_pop: true,
        empty_extensions: ['ext'],
        extra_csr_extensions: ['1.2.3'],
        ku: { critical: true, values: ['digitalSignature'] },
      },
      sans: [{ element: 'dnsname', values: ['a.example.com'] }],
      extensions: [{ type: 'ms_sid', value: 'S-1-5' }],
      ms_private_key_hash: 'hash',
      data_from: 'api',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/lifecycle/enroll', {
      ca: 'ISSUING_CA',
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----',
      template: {
        name: 'ServerCert',
        pathLen: 0,
        lifetime: '365 days',
        backdate: '1 hour',
        checkPoP: true,
        emptyExtensions: ['ext'],
        extraCsrExtensions: ['1.2.3'],
        ku: { critical: true, values: ['digitalSignature'] },
      },
      dn: 'CN=test',
      sans: [{ element: 'dnsname', values: ['a.example.com'] }],
      extensions: [{ type: 'ms_sid', value: 'S-1-5' }],
      msPrivateKeyHash: 'hash',
      dataFrom: 'api',
    });
  });

  it('maps dn_elements to dnElements', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ dn: 'CN=x' });
    await tool('enroll_certificate').h({
      ca: 'CA',
      csr: 'csr-pem',
      template_name: 'T',
      dn_elements: [{ element: 'cn.1', value: 'x' }],
    });
    const body = client.post.mock.calls[0][1];
    expect(body.dnElements).toEqual([{ element: 'cn.1', value: 'x' }]);
    expect(body.template).toEqual({ name: 'T' });
  });

  it('requires a DN source when data_from defaults to api', async () => {
    const { client, tool } = setup();
    const res = await tool('enroll_certificate').h({
      ca: 'CA',
      csr: 'csr-pem',
      template_name: 'T',
    });
    expect(res.isError).toBe(true);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('allows omitting DN when data_from=csr', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ dn: 'CN=fromcsr' });
    await tool('enroll_certificate').h({
      ca: 'CA',
      csr: 'csr-pem',
      template_name: 'T',
      data_from: 'csr',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/lifecycle/enroll', {
      ca: 'CA',
      csr: 'csr-pem',
      template: { name: 'T' },
      dataFrom: 'csr',
    });
  });
});

describe('revoke_certificate', () => {
  it('revokes by PEM certificate (serial/ca ignored)', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ dn: 'CN=z', revoked: true });
    await tool('revoke_certificate').h({
      certificate:
        '-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----',
      reason: 'keyCompromise',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/lifecycle/revoke', {
      reason: 'keyCompromise',
      certificate:
        '-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----',
    });
  });

  it('revokes by serial + ca', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ dn: 'CN=z', revoked: true });
    await tool('revoke_certificate').h({
      serial: 'deadbeef',
      ca: 'ISSUING_CA',
      reason: 'superseded',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/lifecycle/revoke', {
      reason: 'superseded',
      serial: 'deadbeef',
      ca: 'ISSUING_CA',
    });
  });

  it('errors when neither certificate nor serial+ca is provided', async () => {
    const { client, tool } = setup();
    const res = await tool('revoke_certificate').h({
      ca: 'ISSUING_CA',
      reason: 'unspecified',
    });
    expect(res.isError).toBe(true);
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('list_requestable_templates', () => {
  it('lists with no permission param (default search)', async () => {
    const { client, tool } = setup();
    client.getList.mockResolvedValue([
      { ca: 'ASA-RCA', templates: ['A', 'B'] },
    ]);
    const res = await tool('list_requestable_templates').h({});
    expect(client.getList).toHaveBeenCalledWith(
      '/api/v1/lifecycle/templates',
      undefined,
    );
    expect(JSON.parse(lastText(res)).items).toEqual([
      { ca: 'ASA-RCA', templates: ['A', 'B'] },
    ]);
  });

  it('passes the permission query param', async () => {
    const { client, tool } = setup();
    client.getList.mockResolvedValue([]);
    await tool('list_requestable_templates').h({ permission: 'enroll' });
    const [path, params] = client.getList.mock.calls[0];
    expect(path).toBe('/api/v1/lifecycle/templates');
    expect(params.toString()).toBe('permission=enroll');
  });
});
