import { describe, expect, it, vi } from 'vitest';

import { registerX509CaTools } from '../../src/tools/x509-ca/index.js';

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
  registerX509CaTools(server, client as any);
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

const EXTERNAL_CERT =
  '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

describe('x509-ca registration', () => {
  it('registers all 11 required tools (+ describe helper)', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    for (const t of [
      'list_cas',
      'get_ca',
      'create_ca',
      'update_ca',
      'delete_ca',
      'migrate_ca',
      'generate_ca_csr',
      'issue_ca',
      'enhance_ca',
      'generate_crl',
      'upload_crl',
    ]) {
      expect(names, `missing ${t}`).toContain(t);
    }
    expect(names).toContain('describe_ca_schema');
  });
});

describe('list_cas / get_ca', () => {
  it('list_cas uses getList (204 -> [])', async () => {
    const { client, byName } = setup();
    client.getList.mockResolvedValue([]);
    await byName('list_cas').h({ max_items: 50 });
    expect(client.getList).toHaveBeenCalledWith('/api/v1/cas');
  });

  it('get_ca encodes the name into the item path', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({ name: 'My CA' });
    await byName('get_ca').h({ name: 'My CA' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/cas/My%20CA');
  });
});

describe('create_ca', () => {
  it('posts a managed-from-scratch body verbatim (dn + privateKey, no certificate)', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'Root', type: 'managed' });
    const config = {
      type: 'managed',
      name: 'Root',
      enroll: true,
      trustedForClientAuthentication: false,
      trustedForServerAuthentication: false,
      enforceKeyUnicity: false,
      dn: 'CN=Root, C=FR',
      privateKey: { keystore: 'ks', name: 'rootkey', hashAlgorithm: 'SHA256' },
    };
    await byName('create_ca').h({ config });
    expect(client.post).toHaveBeenCalledWith('/api/v1/cas', config);
  });

  it('posts an external import body (certificate + outdatedRevocationStatusPolicy)', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'Ext', type: 'external' });
    const config = {
      type: 'external',
      name: 'Ext',
      certificate: EXTERNAL_CERT,
      trustedForClientAuthentication: true,
      trustedForServerAuthentication: true,
      outdatedRevocationStatusPolicy: 'lastavailablestatus',
      crlUrls: ['http://crl.example/ca.crl'],
    };
    await byName('create_ca').h({ config });
    expect(client.post).toHaveBeenCalledWith('/api/v1/cas', config);
  });

  it('rejects external CA with https:// crlUrls (validation -> isError)', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('create_ca').h({
        config: {
          type: 'external',
          name: 'Ext',
          certificate: EXTERNAL_CERT,
          trustedForClientAuthentication: true,
          trustedForServerAuthentication: true,
          outdatedRevocationStatusPolicy: 'revoked',
          crlUrls: ['https://crl.example/ca.crl'],
        },
      }),
    );
    expect(out).toContain('http://');
    expect(client.post).not.toHaveBeenCalled();
  });

  it('rejects managed CA that omits both dn and certificate', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('create_ca').h({
        config: {
          type: 'managed',
          name: 'X',
          enroll: true,
          trustedForClientAuthentication: false,
          trustedForServerAuthentication: false,
          enforceKeyUnicity: false,
          privateKey: { keystore: 'ks', name: 'k' },
        },
      }),
    );
    expect(out).toContain('dn');
    expect(client.post).not.toHaveBeenCalled();
  });

  it('rejects managed CA carrying external-only fields', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('create_ca').h({
        config: {
          type: 'managed',
          name: 'X',
          enroll: true,
          trustedForClientAuthentication: false,
          trustedForServerAuthentication: false,
          enforceKeyUnicity: false,
          dn: 'CN=X',
          privateKey: { keystore: 'ks', name: 'k' },
          timeout: '5 seconds',
        },
      }),
    );
    expect(out.toLowerCase()).toContain('external-only');
    expect(client.post).not.toHaveBeenCalled();
  });

  it('rejects external CA missing certificate', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('create_ca').h({
        config: {
          type: 'external',
          name: 'Ext',
          trustedForClientAuthentication: true,
          trustedForServerAuthentication: true,
          outdatedRevocationStatusPolicy: 'revoked',
        },
      }),
    );
    expect(out).toContain('certificate');
    expect(client.post).not.toHaveBeenCalled();
  });
});

describe('update_ca', () => {
  it('GET-strip-merge-PUTs: strips certificate/privateKey/dn/revoked*, PUTs collection root', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue({
      id: 'srv-id',
      type: 'managed',
      name: 'Root',
      certificate: { dn: 'CN=Root', pem: 'rich' }, // rich-on-read -> must be stripped
      privateKey: { keystore: 'ks', name: 'k', hashAlgorithm: 'SHA256' },
      dn: null,
      revoked: false,
      enroll: false,
      enforceKeyUnicity: false,
      trustedForClientAuthentication: false,
      trustedForServerAuthentication: false,
      description: 'old',
    });
    let putPath: string | undefined;
    let putBody: any;
    client.put.mockImplementation(async (p: string, b: any) => {
      putPath = p;
      putBody = b;
      return { ...b };
    });

    await byName('update_ca').h({
      config: {
        type: 'managed',
        name: 'Root',
        enroll: true,
        enforceKeyUnicity: false,
        trustedForClientAuthentication: true,
        trustedForServerAuthentication: false,
        description: 'new',
        privateKey: { keystore: 'ks', name: 'k' }, // ignored (stripped)
      },
    });

    expect(client.get).toHaveBeenCalledWith('/api/v1/cas/Root');
    expect(putPath).toBe('/api/v1/cas'); // PUT on collection root
    // server-managed fields stripped
    expect(putBody.id).toBeUndefined();
    expect(putBody.certificate).toBeUndefined();
    expect(putBody.privateKey).toBeUndefined();
    expect(putBody.revoked).toBeUndefined();
    expect(putBody.dn).toBeUndefined();
    // overrides applied
    expect(putBody.enroll).toBe(true);
    expect(putBody.description).toBe('new');
    expect(putBody.trustedForClientAuthentication).toBe(true);
    // preserved from previous
    expect(putBody.name).toBe('Root');
    expect(putBody.type).toBe('managed');
  });
});

describe('delete_ca', () => {
  it('enforces the expected_name echo guard', async () => {
    const { client, byName } = setup();
    const out = await textOf(
      byName('delete_ca').h({ name: 'CA1', expected_name: 'WRONG' }),
    );
    expect(out).toContain('Safety check failed');
    expect(client.delete).not.toHaveBeenCalled();
  });

  it('deletes with matching echo and encodes the path', async () => {
    const { client, byName } = setup();
    client.delete.mockResolvedValue(null);
    await byName('delete_ca').h({ name: 'CA 1', expected_name: 'CA 1' });
    expect(client.delete).toHaveBeenCalledWith('/api/v1/cas/CA%201');
  });
});

describe('migrate_ca', () => {
  it('PATCHes :name with {privateKey, altPrivateKey?} (camelCase)', async () => {
    const { client, byName } = setup();
    client.patch.mockResolvedValue({ name: 'Ext', type: 'managed' });
    await byName('migrate_ca').h({
      name: 'Ext',
      private_key: { keystore: 'ks', name: 'k', hashAlgorithm: 'SHA256' },
      alt_private_key: { keystore: 'pqc', name: 'altk' },
    });
    expect(client.patch).toHaveBeenCalledWith('/api/v1/cas/Ext', {
      privateKey: { keystore: 'ks', name: 'k', hashAlgorithm: 'SHA256' },
      altPrivateKey: { keystore: 'pqc', name: 'altk' },
    });
  });

  it('omits altPrivateKey when not supplied', async () => {
    const { client, byName } = setup();
    client.patch.mockResolvedValue({});
    await byName('migrate_ca').h({
      name: 'Ext',
      private_key: { keystore: 'ks', name: 'k' },
    });
    const body = client.patch.mock.calls[0]![1] as Record<string, unknown>;
    expect(body).toEqual({ privateKey: { keystore: 'ks', name: 'k' } });
    expect('altPrivateKey' in body).toBe(false);
  });
});

describe('generate_ca_csr', () => {
  it('GETs :name/csr as PEM via getText with application/pkcs10', async () => {
    const { client, byName } = setup();
    client.getText.mockResolvedValue(
      '-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----',
    );
    const out = await textOf(byName('generate_ca_csr').h({ name: 'Root CA' }));
    expect(client.getText).toHaveBeenCalledWith(
      '/api/v1/cas/Root%20CA/csr',
      'application/pkcs10',
    );
    expect(out).toContain('BEGIN CERTIFICATE REQUEST');
  });
});

describe('issue_ca', () => {
  it('POSTs :name/issue with {ca, csr, template} mapping issuing_ca -> ca', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'Root' });
    await byName('issue_ca').h({
      name: 'Root',
      issuing_ca: 'Root', // ca == name => root self-sign
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----',
      template: { lifetime: '3650 days', pathLen: 1 },
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/cas/Root/issue', {
      ca: 'Root',
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----',
      template: { lifetime: '3650 days', pathLen: 1 },
    });
  });
});

describe('enhance_ca', () => {
  it('POSTs :name/enhance with a bare SignerPrivateKey body', async () => {
    const { client, byName } = setup();
    client.post.mockResolvedValue({ name: 'Root' });
    await byName('enhance_ca').h({
      name: 'Root',
      alt_private_key: { keystore: 'pqc', name: 'altk' },
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/cas/Root/enhance', {
      keystore: 'pqc',
      name: 'altk',
    });
  });
});

describe('generate_crl', () => {
  it('GETs :name/crl with no lazy param by default', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue(null); // 204
    await byName('generate_crl').h({ name: 'Root' });
    expect(client.get).toHaveBeenCalledWith('/api/v1/cas/Root/crl', undefined);
  });

  it('GETs :name/crl?lazy=true when lazy=true', async () => {
    const { client, byName } = setup();
    client.get.mockResolvedValue(null);
    await byName('generate_crl').h({ name: 'Root', lazy: true });
    const params = client.get.mock.calls[0]![1] as URLSearchParams;
    expect(client.get.mock.calls[0]![0]).toBe('/api/v1/cas/Root/crl');
    expect(params.toString()).toBe('lazy=true');
  });
});

describe('upload_crl', () => {
  it('POSTs multipart with a crl PEM part (no nextRefresh)', async () => {
    const { client, byName } = setup();
    client.postMultipart.mockResolvedValue(null);
    await byName('upload_crl').h({
      name: 'Ext CA',
      crl: '-----BEGIN X509 CRL-----\nX\n-----END X509 CRL-----',
    });
    expect(client.postMultipart).toHaveBeenCalledTimes(1);
    const [path, parts] = client.postMultipart.mock.calls[0]!;
    expect(path).toBe('/api/v1/cas/Ext%20CA/crl');
    expect(parts).toHaveLength(1);
    expect(parts[0].fieldName).toBe('crl');
    expect(parts[0].data).toContain('BEGIN X509 CRL');
  });

  it('adds a nextRefresh text part and base64-decodes DER', async () => {
    const { client, byName } = setup();
    client.postMultipart.mockResolvedValue(null);
    const b64 = Buffer.from('der-bytes').toString('base64');
    await byName('upload_crl').h({
      name: 'Ext',
      crl: b64,
      crl_base64: true,
      next_refresh: '2027-01-01T00:00:00Z',
    });
    const parts = client.postMultipart.mock.calls[0]![1] as any[];
    expect(parts).toHaveLength(2);
    expect(parts[0].fieldName).toBe('crl');
    expect(Buffer.isBuffer(parts[0].data)).toBe(true);
    expect((parts[0].data as Buffer).toString()).toBe('der-bytes');
    expect(parts[1].fieldName).toBe('nextRefresh');
    expect(parts[1].data).toBe('2027-01-01T00:00:00Z');
  });
});
