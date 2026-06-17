import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { Client } from '@modelcontextprotocol/sdk/client/index.js';

import { E2E_CONFIGURED, connectGrounded, toolJson } from './setup.js';

/**
 * Grounded "does the MCP produce USABLE output" tier — calls tools through a
 * real in-process MCP wired to a real StreamClient against QA (no model). $0
 * beyond the QA API calls. Read-only / safe operations only.
 *
 * Skipped automatically when STREAM_E2E_* is not set (source .env.local).
 */
describe.skipIf(!E2E_CONFIGURED)('Grounded MCP tool outputs (live QA)', () => {
  let client: Client;

  beforeAll(async () => {
    client = await connectGrounded();
  });
  afterAll(async () => {
    await client?.close();
  });

  async function call(name: string, args: Record<string, unknown> = {}) {
    const res = (await client.callTool({ name, arguments: args })) as {
      isError?: boolean;
      content?: Array<{ type: string; text?: string }>;
    };
    expect(
      res.isError,
      `${name} returned an error: ${JSON.stringify(res.content)}`,
    ).not.toBe(true);
    return toolJson(res) as Record<string, unknown>;
  }

  it('whoami returns a resolved principal identifier', async () => {
    const me = await call('whoami');
    const identity = (me['identity'] ?? {}) as Record<string, unknown>;
    expect(typeof identity['identifier']).toBe('string');
    expect((identity['identifier'] as string).length).toBeGreaterThan(0);
  });

  it('list_cas returns a usable list envelope', async () => {
    const out = await call('list_cas', { max_items: 5 });
    expect(Array.isArray(out['items'])).toBe(true);
    expect(typeof out['count']).toBe('number');
    expect(out['kind']).toBe('ca');
  });

  it('search_certificates returns a usable paginated envelope', async () => {
    const out = await call('search_certificates', {
      query: 'id exists',
      page_size: 2,
    });
    expect(Array.isArray(out['results'])).toBe(true);
    expect(typeof out['page_index']).toBe('number');
    expect('has_more' in out).toBe(true);
  });

  it('get_license_info returns version + entitled modules', async () => {
    const lic = await call('get_license_info');
    // The instance returns a non-empty license object (fields vary by edition).
    expect(Object.keys(lic).length).toBeGreaterThan(0);
  });

  it('search_docs + get_doc surface usable knowledge content', async () => {
    const search = await call('search_docs', {
      query: 'create a CA from scratch',
    });
    expect(Array.isArray(search['results'])).toBe(true);
    expect((search['results'] as unknown[]).length).toBeGreaterThan(0);

    const doc = (await client.callTool({
      name: 'get_doc',
      arguments: { uri: 'ca-management' },
    })) as { content?: Array<{ type: string; text?: string }> };
    const md = doc.content?.find((c) => c.type === 'text')?.text ?? '';
    expect(md.length).toBeGreaterThan(200);
    expect(md).toContain('CA');
  });
});
