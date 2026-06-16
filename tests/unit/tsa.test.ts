import { describe, expect, it, vi } from 'vitest';

import { registerTsaTools } from '../../src/tools/tsa/index.js';

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
  registerTsaTools(server, client);
  const byName = (name: string) => {
    const tool = calls.find((t) => t.n === name);
    if (!tool) throw new Error(`tool not registered: ${name}`);
    return tool;
  };
  const invoke = (name: string, args: any) => byName(name).h(args, {} as any);
  return { calls, server, client, byName, invoke };
}

describe('tsa domain registration', () => {
  it('registers exactly the 16 expected tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual(
      [
        'create_ntp_client',
        'create_tsa_authority',
        'create_tsa_signer',
        'delete_ntp_client',
        'delete_tsa_authority',
        'delete_tsa_signer',
        'generate_tsa_signer_csr',
        'get_ntp_client',
        'get_tsa_authority',
        'get_tsa_signer',
        'list_ntp_clients',
        'list_tsa_authorities',
        'list_tsa_signers',
        'update_ntp_client',
        'update_tsa_authority',
        'update_tsa_signer',
      ].sort(),
    );
  });
});

describe('timestamping authorities', () => {
  it('list_tsa_authorities uses getList on the collection', async () => {
    const { client, invoke } = setup();
    client.getList.mockResolvedValue([{ name: 'A1' }]);
    await invoke('list_tsa_authorities', { max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith(
      '/api/v1/timestamping/authorities',
    );
  });

  it('get_tsa_authority GETs the item route with encoded name', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({ name: 'My TSA' });
    await invoke('get_tsa_authority', { name: 'My TSA' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/timestamping/authorities/My%20TSA',
    );
  });

  it('create_tsa_authority POSTs the full camelCase body', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'lccEncryptionTestTSA' });
    await invoke('create_tsa_authority', {
      name: 'lccEncryptionTestTSA',
      policy_oid: '1.1',
      enabled: true,
      signer: 'lccTSS',
      accepted_hash_algorithms: ['SHA256', 'SHA3_256'],
      ntp_clients: ['lccGoogle'],
      check_revocation: false,
    });
    expect(client.post).toHaveBeenCalledWith(
      '/api/v1/timestamping/authorities',
      {
        name: 'lccEncryptionTestTSA',
        policyOid: '1.1',
        enabled: true,
        signer: 'lccTSS',
        acceptedHashAlgorithms: ['SHA256', 'SHA3_256'],
        ntpClients: ['lccGoogle'],
        checkRevocation: false,
      },
    );
  });

  it('update_tsa_authority does GET-strip-merge-PUT stripping id, full-replace on collection', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'TSA1',
      policyOid: '1.1',
      enabled: true,
      signer: 'old-signer',
      acceptedHashAlgorithms: ['SHA256'],
      ntpClients: ['ntp1'],
      checkRevocation: false,
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_tsa_authority', {
      name: 'TSA1',
      signer: 'new-signer',
      ntp_clients: ['ntp1', 'ntp2'],
    });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/timestamping/authorities/TSA1',
    );
    expect(client.put.mock.calls[0][0]).toBe(
      '/api/v1/timestamping/authorities',
    );
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.id).toBeUndefined();
    expect(putBody.name).toBe('TSA1');
    expect(putBody.signer).toBe('new-signer');
    expect(putBody.ntpClients).toEqual(['ntp1', 'ntp2']);
    // untouched fields preserved from GET
    expect(putBody.policyOid).toBe('1.1');
    expect(putBody.acceptedHashAlgorithms).toEqual(['SHA256']);
  });

  it('delete_tsa_authority enforces the echo guard then deletes', async () => {
    const { client, invoke } = setup();
    const bad = await invoke('delete_tsa_authority', {
      name: 'TSA1',
      expected_name: 'WRONG',
    });
    expect(bad.isError).toBe(true);
    expect(client.delete).not.toHaveBeenCalled();

    client.delete.mockResolvedValue(null);
    await invoke('delete_tsa_authority', {
      name: 'TSA1',
      expected_name: 'TSA1',
    });
    expect(client.delete).toHaveBeenCalledWith(
      '/api/v1/timestamping/authorities/TSA1',
    );
  });
});

describe('timestamping signers', () => {
  it('list_tsa_signers uses getList on the signer collection', async () => {
    const { client, invoke } = setup();
    client.getList.mockResolvedValue([{ name: 'S1' }]);
    await invoke('list_tsa_signers', { max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/timestamping/signers');
  });

  it('create_tsa_signer POSTs camelCase body with dn and omits the certificate', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'lccTSS' });
    await invoke('create_tsa_signer', {
      name: 'lccTSS',
      dn: 'CN=lccTSS',
      private_key: {
        keystore: 'lccEncryptionTestKeystore',
        name: 'lccEncryptionTSSKey',
        hash_algorithm: 'SHA256',
        use_pss: true,
      },
      queue: 'q1',
      on_expiration_triggers: ['notify-team'],
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/timestamping/signers', {
      name: 'lccTSS',
      dn: 'CN=lccTSS',
      privateKey: {
        keystore: 'lccEncryptionTestKeystore',
        name: 'lccEncryptionTSSKey',
        hashAlgorithm: 'SHA256',
        usePSS: true,
      },
      queue: 'q1',
      triggers: { onTSASignerExpiration: ['notify-team'] },
    });
    const sent = client.post.mock.calls[0][1];
    expect('certificate' in sent).toBe(false);
  });

  it('create_tsa_signer omits optional fields when not supplied', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'S' });
    await invoke('create_tsa_signer', {
      name: 'S',
      dn: 'CN=S',
      private_key: { keystore: 'KS', name: 'K' },
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/timestamping/signers', {
      name: 'S',
      dn: 'CN=S',
      privateKey: { keystore: 'KS', name: 'K' },
    });
  });

  it('update_tsa_signer strips id/certificate and sends certificate_pem as a PEM string', async () => {
    const { client, invoke } = setup();
    // A cert-bearing signer: the server forced dn=None, so the GET has no `dn`.
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'S1',
      certificate: { dn: 'CN=rich', pem: 'PEM' }, // rich-on-read; must strip
      privateKey: { keystore: 'KS', name: 'K', hashAlgorithm: 'SHA256' },
      triggers: {},
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    const pem =
      '-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----';
    await invoke('update_tsa_signer', {
      name: 'S1',
      certificate_pem: pem,
    });
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/timestamping/signers');
    const putBody = client.put.mock.calls[0][1];
    // stripped from GET
    expect(putBody.id).toBeUndefined();
    // certificate overridden as a write-only PEM string (not the rich object)
    expect(putBody.certificate).toBe(pem);
    expect(typeof putBody.certificate).toBe('string');
    expect(putBody.name).toBe('S1');
    expect(putBody.privateKey).toEqual({
      keystore: 'KS',
      name: 'K',
      hashAlgorithm: 'SHA256',
    });
  });

  it('update_tsa_signer preserves dn from GET when the signer has no certificate (server requires it)', async () => {
    const { client, invoke } = setup();
    // A PEM-less signer: dn is mandatory. The GET-strip-merge-PUT must NOT drop
    // dn, else the server rejects the PUT (TIMESTAMPING-SIGNER-002 "dn is
    // mandatory when certificate is not specified"). Verified live on QA.
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'S1',
      dn: 'CN=S1',
      privateKey: { keystore: 'KS', name: 'K', hashAlgorithm: 'SHA256' },
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_tsa_signer', {
      name: 'S1',
      private_key: { keystore: 'KS', name: 'K', hash_algorithm: 'SHA384' },
    });
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.id).toBeUndefined();
    // dn carried through from the GET (not stripped)
    expect(putBody.dn).toBe('CN=S1');
    expect(putBody.privateKey).toEqual({
      keystore: 'KS',
      name: 'K',
      hashAlgorithm: 'SHA384',
    });
  });

  it('update_tsa_signer maps a supplied private_key override to camelCase', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'i',
      name: 'S1',
      privateKey: { keystore: 'A', name: 'B' },
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_tsa_signer', {
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

  it('delete_tsa_signer enforces the echo guard then deletes', async () => {
    const { client, invoke } = setup();
    const bad = await invoke('delete_tsa_signer', {
      name: 'S1',
      expected_name: 'NOPE',
    });
    expect(bad.isError).toBe(true);
    expect(client.delete).not.toHaveBeenCalled();

    client.delete.mockResolvedValue(null);
    await invoke('delete_tsa_signer', { name: 'S1', expected_name: 'S1' });
    expect(client.delete).toHaveBeenCalledWith(
      '/api/v1/timestamping/signers/S1',
    );
  });

  it('generate_tsa_signer_csr fetches PEM via getText with pkcs10 accept', async () => {
    const { client, invoke } = setup();
    client.getText.mockResolvedValue(
      '-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----',
    );
    const result = await invoke('generate_tsa_signer_csr', {
      name: 'mike signer',
    });
    expect(client.getText).toHaveBeenCalledWith(
      '/api/v1/timestamping/signers/mike%20signer/csr',
      'application/pkcs10',
    );
    expect(result.content[0].text).toContain('BEGIN CERTIFICATE REQUEST');
  });
});

describe('ntp clients', () => {
  it('list_ntp_clients uses getList on the ntps collection', async () => {
    const { client, invoke } = setup();
    client.getList.mockResolvedValue([{ name: 'N1' }]);
    await invoke('list_ntp_clients', { max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/timestamping/ntps');
  });

  it('get_ntp_client GETs the item route with encoded name', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({ name: 'lccGoogle' });
    await invoke('get_ntp_client', { name: 'lccGoogle' });
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/timestamping/ntps/lccGoogle',
    );
  });

  it('create_ntp_client POSTs camelCase body mapping max_rtt -> maxRTT', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'badNtp' });
    await invoke('create_ntp_client', {
      name: 'badNtp',
      host: 'time1.google.com',
      description: 'google ntp',
      port: 123,
      timeout: '10 seconds',
      max_stratum: 0,
      max_offset: '100 ms',
      max_rtt: 250,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/timestamping/ntps', {
      name: 'badNtp',
      host: 'time1.google.com',
      description: 'google ntp',
      port: 123,
      timeout: '10 seconds',
      maxStratum: 0,
      maxOffset: '100 ms',
      maxRTT: 250,
    });
  });

  it('create_ntp_client omits optional fields when not supplied', async () => {
    const { client, invoke } = setup();
    client.post.mockResolvedValue({ name: 'lccGoogle' });
    await invoke('create_ntp_client', {
      name: 'lccGoogle',
      host: 'time1.google.com',
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/timestamping/ntps', {
      name: 'lccGoogle',
      host: 'time1.google.com',
    });
  });

  it('update_ntp_client does GET-strip-merge-PUT stripping id, full-replace on collection', async () => {
    const { client, invoke } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      name: 'N1',
      host: 'old.host.com',
      timeout: '5 s',
    });
    client.put.mockImplementation(async (_p: string, body: any) => body);
    await invoke('update_ntp_client', {
      name: 'N1',
      host: 'new.host.com',
      max_stratum: 4,
    });
    expect(client.get).toHaveBeenCalledWith('/api/v1/timestamping/ntps/N1');
    expect(client.put.mock.calls[0][0]).toBe('/api/v1/timestamping/ntps');
    const putBody = client.put.mock.calls[0][1];
    expect(putBody.id).toBeUndefined();
    expect(putBody.name).toBe('N1');
    expect(putBody.host).toBe('new.host.com');
    expect(putBody.maxStratum).toBe(4);
    // untouched field preserved
    expect(putBody.timeout).toBe('5 s');
  });

  it('delete_ntp_client enforces the echo guard then deletes', async () => {
    const { client, invoke } = setup();
    const bad = await invoke('delete_ntp_client', {
      name: 'N1',
      expected_name: 'X',
    });
    expect(bad.isError).toBe(true);
    expect(client.delete).not.toHaveBeenCalled();

    client.delete.mockResolvedValue(null);
    await invoke('delete_ntp_client', { name: 'N1', expected_name: 'N1' });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/timestamping/ntps/N1');
  });
});
