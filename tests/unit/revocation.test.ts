import { describe, expect, it, vi } from 'vitest';

import { registerRevocationTools } from '../../src/tools/revocation/index.js';

interface RegisteredTool {
  n: string;
  c: any;
  h: (...args: any[]) => any;
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
  registerRevocationTools(server, client);
  const byName = (name: string) => {
    const tool = calls.find((t) => t.n === name);
    if (!tool) throw new Error(`tool not registered: ${name}`);
    return tool;
  };
  // Tool handlers receive (args, extra); MCP passes parsed args. We invoke the
  // handler directly with the args object.
  const invoke = (name: string, args: any) => byName(name).h(args, {} as any);
  return { calls, server, client, byName, invoke };
}

const FUTURE_ISO = '2099-12-31T00:00:00Z';

function parseText(result: any): any {
  const txt = result.content[0].text;
  try {
    return JSON.parse(txt);
  } catch {
    return txt;
  }
}

describe('revocation domain registration', () => {
  it('registers exactly the 12 expected tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual(
      [
        'assign_ocsp_signer_to_ca',
        'create_ocsp_signer',
        'delete_ocsp_signer',
        'generate_ocsp_signer_csr',
        'get_crl',
        'get_published_crl',
        'get_published_aia',
        'get_ocsp_signer',
        'list_crls',
        'list_ocsp_signers',
        'update_crl_next_refresh',
        'update_ocsp_signer',
      ].sort(),
    );
  });
});

describe('CRL tools', () => {
  it('list_crls uses getList on the collection and filters by ca', async () => {
    const { client, invoke } = setup();
    client.getList.mockResolvedValue([
      { ca: 'ASA-RCA', type: 'managed', size: 0 },
      { ca: 'OTHER-CA', type: 'external', size: 0 },
    ]);
    const result = await invoke('list_crls', {
      max_items: 50,
      ca_contains: 'asa',
    });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/crls');
    const body = parseText(result);
    expect(body.kind).toBe('crl');
    expect(body.items).toHaveLength(1);
    expect(body.items[0].ca).toBe('ASA-RCA');
  });

  it('get_crl GETs /crls/:ca with the encoded ca segment', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({ ca: 'ASA-RCA', number: 298 });
    await invoke('get_crl', { ca: 'ASA-RCA' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/crls/ASA-RCA');
  });

  it('update_crl_next_refresh PUTs {nextRefresh} keyed by :ca', async () => {
    const { client, invoke } = setup();
    client.put.mockResolvedValue({ ca: 'ASA-RCA', nextRefresh: FUTURE_ISO });
    const result = await invoke('update_crl_next_refresh', {
      ca: 'ASA-RCA',
      next_refresh: FUTURE_ISO,
    });
    expect(client.put).toHaveBeenCalledWith('/api/v1/crls/ASA-RCA', {
      nextRefresh: FUTURE_ISO,
    });
    const body = parseText(result);
    expect(body.status).toBe('updated');
    expect(body.kind).toBe('crl');
    expect(body.name).toBe('ASA-RCA');
  });

  it('update_crl_next_refresh rejects a non-future instant (no-op guard)', async () => {
    const { client, invoke } = setup();
    // registerTool wraps client-side StreamErrors into an isError result.
    const result = await invoke('update_crl_next_refresh', {
      ca: 'ASA-RCA',
      next_refresh: '2000-01-01T00:00:00Z',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/future/i);
    expect(client.put).not.toHaveBeenCalled();
  });

  it('update_crl_next_refresh rejects a malformed instant', async () => {
    const { client, invoke } = setup();
    const result = await invoke('update_crl_next_refresh', {
      ca: 'ASA-RCA',
      next_refresh: 'not-a-date',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/valid ISO/i);
    expect(client.put).not.toHaveBeenCalled();
  });
});

describe('OCSP signer CRUD', () => {
  it('list_ocsp_signers uses getList on the signer collection', async () => {
    const { client, invoke } = setup();
    client.getList.mockResolvedValue([{ name: 'S1' }]);
    await invoke('list_ocsp_signers', { max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/ocsp/signers');
  });

  it('get_ocsp_signer GETs the item route with encoded name', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({ name: 'My Signer' });
    await invoke('get_ocsp_signer', { name: 'My Signer' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/ocsp/signers/My%20Signer');
  });

  it('create_ocsp_signer POSTs camelCase body and omits the certificate', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'MY-OCSP-SIGNER' });
    await invoke('create_ocsp_signer', {
      name: 'MY-OCSP-SIGNER',
      dn: 'CN=MY-OCSP-SIGNER',
      private_key: {
        keystore: 'MY-KEYSTORE',
        name: 'MY-OCSP-KEY',
        hash_algorithm: 'SHA256',
        use_pss: true,
      },
      queue: 'q1',
      on_expiration_triggers: ['notify-team'],
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/ocsp/signers', {
      name: 'MY-OCSP-SIGNER',
      dn: 'CN=MY-OCSP-SIGNER',
      privateKey: {
        keystore: 'MY-KEYSTORE',
        name: 'MY-OCSP-KEY',
        hashAlgorithm: 'SHA256',
        usePSS: true,
      },
      queue: 'q1',
      triggers: { onOCSPSignerExpiration: ['notify-team'] },
    });
    // certificate must NOT be sent on create.
    const sent = client.post.mock.calls[0][1];
    expect('certificate' in sent).toBe(false);
  });

  it('create_ocsp_signer omits optional fields when not supplied', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'S' });
    await invoke('create_ocsp_signer', {
      name: 'S',
      dn: 'CN=S',
      private_key: { keystore: 'KS', name: 'K' },
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/ocsp/signers', {
      name: 'S',
      dn: 'CN=S',
      privateKey: { keystore: 'KS', name: 'K' },
    });
  });

  it('update_ocsp_signer does GET-strip-merge-PUT stripping id/certificate but PRESERVING dn', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'S1',
      certificate: { dn: 'CN=rich', pem: 'PEM' }, // rich-on-read; must strip
      dn: 'CN=old', // NOT stripped (mandatory for cert-less signers; server forces None when a cert exists)
      privateKey: { keystore: 'KS', name: 'K', hashAlgorithm: 'SHA256' },
      queue: 'oldq',
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_ocsp_signer', {
      name: 'S1',
      queue: 'newq',
    });
    // PUT targets the COLLECTION route (putOnCollection).
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/ocsp/signers');
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.id).toBeUndefined();
    expect(putBody.certificate).toBeUndefined();
    // dn is preserved from the GET (not in stripFields).
    expect(putBody.dn).toBe('CN=old');
    expect(putBody.name).toBe('S1');
    expect(putBody.privateKey).toEqual({
      keystore: 'KS',
      name: 'K',
      hashAlgorithm: 'SHA256',
    });
    expect(putBody.queue).toBe('newq');
  });

  it('update_ocsp_signer keeps the mandatory dn for a cert-less signer (OCSP-SIGNER-002 guard)', async () => {
    // Regression: a cert-less signer requires `dn` on the PUT
    // ("dn is mandatory when certificate is not specified"). Stripping dn from
    // the GET-strip-merge-PUT cycle dropped it and the server rejected the PUT.
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'S1',
      dn: 'CN=S1', // cert-less signer: dn is the only subject source and is mandatory
      privateKey: { keystore: 'KS', name: 'K', hashAlgorithm: 'SHA384' },
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_ocsp_signer', {
      name: 'S1',
      private_key: { keystore: 'KS', name: 'K', hash_algorithm: 'SHA256' },
    });
    const putBody = client.put.mock.calls[0][1];
    // The mandatory dn survives so the server-side invariant is satisfied.
    expect(putBody.dn).toBe('CN=S1');
    expect(putBody.id).toBeUndefined();
    expect(putBody.privateKey).toEqual({
      keystore: 'KS',
      name: 'K',
      hashAlgorithm: 'SHA256',
    });
  });

  it('update_ocsp_signer maps a supplied private_key override to camelCase', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'i',
      name: 'S1',
      privateKey: { keystore: 'A', name: 'B' },
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_ocsp_signer', {
      name: 'S1',
      private_key: {
        keystore: 'A',
        name: 'B',
        hash_algorithm: 'SHA384',
        use_pss: false,
      },
    });
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.privateKey).toEqual({
      keystore: 'A',
      name: 'B',
      hashAlgorithm: 'SHA384',
      usePSS: false,
    });
  });

  it('delete_ocsp_signer enforces the expected_name echo guard', async () => {
    const { client, invoke } = setup();
    const result = await invoke('delete_ocsp_signer', {
      name: 'S1',
      expected_name: 'WRONG',
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Safety check/i);
    expect(client.delete).not.toHaveBeenCalled();
  });

  it('delete_ocsp_signer deletes when the echo matches', async () => {
    const { client, invoke } = setup();
    client.delete.mockResolvedValue(null);
    await invoke('delete_ocsp_signer', { name: 'S1', expected_name: 'S1' });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/ocsp/signers/S1');
  });
});

describe('CSR + CA assignment', () => {
  it('generate_ocsp_signer_csr fetches PEM via getText with pkcs10 accept', async () => {
    const { client, invoke } = setup();
    client.getText.mockResolvedValue(
      '-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----',
    );
    const result = await invoke('generate_ocsp_signer_csr', {
      name: 'My Signer',
    });
    expect(client.getText).toHaveBeenCalledWith(
      '/api/v1/ocsp/signers/My%20Signer/csr',
      'application/pkcs10',
    );
    expect(result.content[0].text).toContain('BEGIN CERTIFICATE REQUEST');
  });

  it('assign_ocsp_signer_to_ca GETs the CA, strips only server-managed fields, PRESERVES privateKey+dn, PUTs enableOCSP+ocspSigner', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'ca-id',
      name: 'ASA-RCA',
      type: 'managed',
      certificate: { pem: 'PEM' },
      privateKey: { keystore: 'KS', name: 'K' },
      altPrivateKey: { keystore: 'PQC', name: 'AK' },
      revoked: false,
      revocationDate: null,
      revocationReason: null,
      dn: 'CN=ASA-RCA',
      description: 'root',
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    const result = await invoke('assign_ocsp_signer_to_ca', {
      ca: 'ASA-RCA',
      ocsp_signer: 'LME-OCSP-SIGNER',
    });
    expect(client.get).toHaveBeenCalledWith('/api/v1/cas/ASA-RCA');
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/cas');
    const putBody = client.put.mock.calls[0][1];
    // overrides applied
    expect(putBody.enableOCSP).toBe(true);
    expect(putBody.ocspSigner).toBe('LME-OCSP-SIGNER');
    // server-managed / rich-on-read fields stripped
    for (const stripped of [
      'id',
      'certificate',
      'altPrivateKey',
      'revoked',
      'revocationDate',
      'revocationReason',
    ]) {
      expect(putBody[stripped]).toBeUndefined();
    }
    // privateKey + dn MUST survive: the CA PUT deserializes into the model
    // (privateKey is non-optional, dn is mandatory cert-less) BEFORE
    // updateFrom() runs; stripping them yields CA-002 "/privateKey:
    // error.path.missing" (verified live). The server keeps the previous
    // privateKey / forces dn None for a certificated CA.
    expect(putBody.privateKey).toEqual({ keystore: 'KS', name: 'K' });
    expect(putBody.dn).toBe('CN=ASA-RCA');
    // benign fields preserved
    expect(putBody.name).toBe('ASA-RCA');
    expect(putBody.type).toBe('managed');
    expect(putBody.description).toBe('root');
    const body = parseText(result);
    expect(body.status).toBe('updated');
    expect(body.kind).toBe('ca');
  });

  it('assign_ocsp_signer_to_ca keeps the mandatory privateKey+dn for a managed-pending CA (CA-002 guard)', async () => {
    // Regression: a managed-pending CA (no certificate) requires both privateKey
    // and dn on the PUT. The previous strip set dropped them and the server
    // rejected the assign with CA-002 "/privateKey: error.path.missing".
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'ca-id',
      name: 'mcpx-revocation-ca',
      type: 'managed',
      trustedForClientAuthentication: false,
      trustedForServerAuthentication: false,
      enroll: false,
      dn: 'CN=mcpx-revocation-ca, C=FR',
      privateKey: { keystore: 'KS', name: 'K', hashAlgorithm: 'SHA256' },
      enforceKeyUnicity: false,
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('assign_ocsp_signer_to_ca', {
      ca: 'mcpx-revocation-ca',
      ocsp_signer: 'mcpx-revocation-signer',
    });
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.privateKey).toEqual({
      keystore: 'KS',
      name: 'K',
      hashAlgorithm: 'SHA256',
    });
    expect(putBody.dn).toBe('CN=mcpx-revocation-ca, C=FR');
    expect(putBody.enableOCSP).toBe(true);
    expect(putBody.ocspSigner).toBe('mcpx-revocation-signer');
    expect(putBody.id).toBeUndefined();
  });
});
