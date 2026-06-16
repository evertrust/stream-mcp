import { describe, expect, it, vi } from 'vitest';

import type { StreamClient } from '../../src/client/http.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
} from '../../src/tools/_scaffold.js';

const SPEC: ConfigSpec = {
  noun: 'widget',
  nounPlural: 'widgets',
  label: 'Widget',
  routeCollection: '/api/v1/widgets',
  routeItem: '/api/v1/widgets/{name}',
  idField: 'name',
  immutableKeys: ['name'],
  stripFields: ['id', 'certificate'],
  putOnCollection: true,
};

describe('getStripMergePutExplicit', () => {
  it('strips server fields, merges overrides, and PUTs the full body', async () => {
    const current = {
      id: 'srv-id',
      name: 'w1',
      certificate: { dn: 'CN=rich-object' }, // rich-on-read; must be stripped
      description: 'old',
      enabled: true,
    };
    let putBody: any;
    const client = {
      get: vi.fn().mockResolvedValue(current),
      put: vi.fn().mockImplementation(async (_path: string, body: any) => {
        putBody = body;
        return { ...body, id: 'srv-id' };
      }),
    } as unknown as StreamClient;

    await getStripMergePutExplicit(
      client,
      '/api/v1/widgets/w1',
      SPEC.routeCollection,
      SPEC.stripFields,
      { description: 'new' },
    );

    // stripped: id + certificate; merged: description; preserved: name, enabled
    expect(putBody).toEqual({ name: 'w1', description: 'new', enabled: true });
    expect(putBody.certificate).toBeUndefined();
    expect(putBody.id).toBeUndefined();
  });

  it('honors clearFields by nulling them', async () => {
    const client = {
      get: vi.fn().mockResolvedValue({ id: 'x', name: 'w', proxy: 'p' }),
      put: vi.fn().mockImplementation(async (_p: string, body: any) => body),
    } as unknown as StreamClient;

    const result = (await getStripMergePutExplicit(
      client,
      '/api/v1/widgets/w',
      SPEC.routeCollection,
      SPEC.stripFields,
      {},
      ['proxy'],
    )) as Record<string, unknown>;

    expect(result.proxy).toBeNull();
  });
});
