import { describe, expect, it, vi } from 'vitest';

import { registerX509TemplateTools } from '../../src/tools/x509-template/index.js';
import { ekuSchema } from '../../src/tools/x509-template/schemas.js';

interface RegisteredTool {
  n: string;
  c: any;
  h: (args: any) => Promise<any>;
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
  } as any;
  registerX509TemplateTools(server, client);
  const byName = (name: string) => {
    const t = calls.find((c) => c.n === name);
    if (!t) throw new Error(`tool not registered: ${name}`);
    return t;
  };
  return { calls, server, client, byName };
}

describe('registerX509TemplateTools', () => {
  it('registers exactly the 5 expected tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual(
      [
        'create_template',
        'delete_template',
        'get_template',
        'list_templates',
        'update_template',
      ].sort(),
    );
  });

  it('list_templates uses getList against the collection route (204 -> [])', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    const res = await byName('list_templates').h({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/templates');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.items).toEqual([]);
    expect(parsed.kind).toBe('template');
  });

  it('get_template GETs the encoded item route', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({ name: 'ms-template' });
    await byName('get_template').h({ name: 'ms-template' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/templates/ms-template');
  });

  it('create_template POSTs the full camelCase wire body', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ id: 'srv1', name: 'my-tls-server' });

    await byName('create_template').h({
      name: 'my-tls-server',
      lifetime: '365d',
      enabled: true,
      crldps_from_ca: false,
      aia_from_ca: false,
      policy_from_ca: false,
      qc_statement_from_ca: false,
      ku: { critical: true, values: ['digitalSignature', 'keyEncipherment'] },
      eku: {
        critical: false,
        values: [{ name: 'serverAuth', oid: '1.3.6.1.5.5.7.3.1' }],
      },
      empty_extensions: ['no_revocation_check'],
      path_len: 1,
      check_pop: false,
      remove_basic_constraints: true,
      extra_csr_extensions: ['1.2', '1.1'],
    });

    expect(client.post).toHaveBeenCalledTimes(1);
    const [path, body] = client.post.mock.calls[0];
    expect(path).toBe('/api/v1/templates');
    // exact camelCase wire mapping + FiniteDuration passthrough
    expect(body).toEqual({
      name: 'my-tls-server',
      lifetime: '365d',
      enabled: true,
      crldpsFromCA: false,
      aiaFromCA: false,
      policyFromCA: false,
      qcStatementFromCA: false,
      ku: { critical: true, values: ['digitalSignature', 'keyEncipherment'] },
      eku: {
        critical: false,
        values: [{ name: 'serverAuth', oid: '1.3.6.1.5.5.7.3.1' }],
      },
      emptyExtensions: ['no_revocation_check'],
      pathLen: 1,
      checkPoP: false,
      removeBasicConstraints: true,
      extraCsrExtensions: ['1.2', '1.1'],
    });
    // no `id` ever sent
    expect('id' in body).toBe(false);
  });

  it('create_template maps qcStatement, privateKeyUsagePeriod, subject, sans verbatim', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'full' });

    await byName('create_template').h({
      name: 'full',
      lifetime: '365 days',
      enabled: true,
      crldps_from_ca: true,
      aia_from_ca: true,
      policy_from_ca: true,
      qc_statement_from_ca: false,
      ku: { critical: true, values: ['digitalSignature'] },
      qc_statement: {
        eTSIQCCompliance: true,
        eTSIQCSSCD: false,
        eTSIRetentionPeriod: 0,
        eTSIQCType: 'ESIGN',
      },
      private_key_usage_period: {
        notBefore: '2026-01-01T00:00:00Z',
        notAfter: '2027-01-01T00:00:00Z',
      },
      subject: [{ type: 'CN', mandatory: true, editable: false, value: 'x' }],
      sans: [{ type: 'DNSNAME', min: 1, max: 1 }],
      aia: { certificate: ['http://aia'], ocsp: [] },
      policy: [{ oid: '2.23.146.1.2.1.3', noticeNumbers: [] }],
    });

    const body = client.post.mock.calls[0][1];
    expect(body.qcStatement).toEqual({
      eTSIQCCompliance: true,
      eTSIQCSSCD: false,
      eTSIRetentionPeriod: 0,
      eTSIQCType: 'ESIGN',
    });
    expect(body.privateKeyUsagePeriod).toEqual({
      notBefore: '2026-01-01T00:00:00Z',
      notAfter: '2027-01-01T00:00:00Z',
    });
    expect(body.subject).toEqual([
      { type: 'CN', mandatory: true, editable: false, value: 'x' },
    ]);
    expect(body.sans).toEqual([{ type: 'DNSNAME', min: 1, max: 1 }]);
    expect(body.aia).toEqual({ certificate: ['http://aia'], ocsp: [] });
    expect(body.policy).toEqual([
      { oid: '2.23.146.1.2.1.3', noticeNumbers: [] },
    ]);
  });

  it('create_template omits undefined optionals from the body', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'min' });
    await byName('create_template').h({
      name: 'min',
      lifetime: '365d',
      enabled: true,
      crldps_from_ca: false,
      aia_from_ca: false,
      policy_from_ca: false,
      qc_statement_from_ca: false,
      ku: { critical: true, values: ['digitalSignature'] },
    });
    const body = client.post.mock.calls[0][1];
    expect(Object.keys(body).sort()).toEqual(
      [
        'name',
        'lifetime',
        'enabled',
        'crldpsFromCA',
        'aiaFromCA',
        'policyFromCA',
        'qcStatementFromCA',
        'ku',
      ].sort(),
    );
    expect('aia' in body).toBe(false);
    expect('subject' in body).toBe(false);
  });

  it('create_template requires ku with at least one value (preValidate)', async () => {
    const { client, byName } = setup();
    // ku present but empty values -> rejected, no POST.
    const empty = await byName('create_template').h({
      name: 'no-ku',
      lifetime: '365d',
      enabled: true,
      crldps_from_ca: false,
      aia_from_ca: false,
      policy_from_ca: false,
      qc_statement_from_ca: false,
      ku: { critical: true, values: [] },
    });
    expect(empty.content[0].text).toMatch(/at least one Key Usage value/);
    expect(client.post).not.toHaveBeenCalled();
  });

  it('create_template lists ku as a mandatory field in its description', () => {
    const { byName } = setup();
    expect(byName('create_template').c.description).toMatch(/MANDATORY[^]*ku/);
  });

  it('update_template GET-strips id, merges overrides (camelCase), PUTs to collection root', async () => {
    const { client, byName } = setup();
    // current record as read back (id present, FiniteDuration human form)
    client.get.mockResolvedValue({
      id: '68ef67bb3b69f44269cb7228',
      name: 'ADCS-CA',
      lifetime: '365 days',
      enabled: true,
      crldpsFromCA: true,
      aiaFromCA: true,
      policyFromCA: true,
      qcStatementFromCA: true,
      ku: { critical: true, values: ['keyCertSign', 'cRLSign'] },
    });
    client.put.mockImplementation(async (_p: string, b: any) => b);

    await byName('update_template').h({
      name: 'ADCS-CA',
      enabled: false,
      path_len: 2,
    });

    // GET on item path, PUT on collection root (putOnCollection)
    expect(client.get).toHaveBeenCalledWith('/api/v1/templates/ADCS-CA');
    const [putPath, putBody] = client.put.mock.calls[0];
    expect(putPath).toBe('/api/v1/templates');
    // id stripped
    expect('id' in putBody).toBe(false);
    // override merged + mapped to camelCase
    expect(putBody.enabled).toBe(false);
    expect(putBody.pathLen).toBe(2);
    // preserved fields from current
    expect(putBody.name).toBe('ADCS-CA');
    expect(putBody.crldpsFromCA).toBe(true);
    expect(putBody.ku).toEqual({
      critical: true,
      values: ['keyCertSign', 'cRLSign'],
    });
  });

  it('update_template honors clear_fields by nulling them', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({
      id: 'x',
      name: 't',
      aia: { certificate: ['http://aia'] },
      aiaFromCA: false,
    });
    client.put.mockImplementation(async (_p: string, b: any) => b);

    await byName('update_template').h({
      name: 't',
      clear_fields: ['aia'],
    });
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.aia).toBeNull();
  });

  it('update_template rejects clear_fields targeting id/name', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({ id: 'x', name: 't' });
    // registerTool wraps StreamError into an isError result rather than throwing.
    const res = await byName('update_template').h({
      name: 't',
      clear_fields: ['id'],
    });
    expect(res.isError).toBe(true);
    expect(res.structuredContent.errorCode).toBe('CONFIG-CLEAR-FORBIDDEN');
    expect(client.put).not.toHaveBeenCalled();
  });

  it('delete_template enforces the expected_name echo guard', async () => {
    const { client, byName } = setup();
    const res = await byName('delete_template').h({
      name: 'tls',
      expected_name: 'WRONG',
    });
    expect(res.isError).toBe(true);
    expect(res.structuredContent.errorCode).toBe('SAFETY-ECHO');
    expect(client.delete).not.toHaveBeenCalled();
  });

  it('delete_template DELETEs the encoded item route when the guard matches', async () => {
    const { client, byName } = setup();
    client.delete.mockResolvedValue(null);
    const res = await byName('delete_template').h({
      name: 'tls',
      expected_name: 'tls',
    });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/templates/tls');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed).toEqual({ deleted: true, name: 'tls', kind: 'template' });
  });

  it('delete tool has destructive annotations', () => {
    const { byName } = setup();
    expect(byName('delete_template').c.annotations.destructiveHint).toBe(true);
    expect(byName('list_templates').c.annotations.readOnlyHint).toBe(true);
  });

  // Live regression: the server REQUIRES eku.values[].custom on input and 400s
  // ("/eku/values(0)/custom: error.path.missing") when it is absent. The schema
  // defaults it to false so a parsed eku value always carries it on the wire.
  it('eku value custom defaults to false when omitted (parsed via schema)', () => {
    const parsed = ekuSchema.parse({
      critical: false,
      values: [{ name: 'serverAuth', oid: '1.3.6.1.5.5.7.3.1' }],
    });
    expect(parsed.values[0]).toEqual({
      name: 'serverAuth',
      oid: '1.3.6.1.5.5.7.3.1',
      custom: false,
    });
  });
});
