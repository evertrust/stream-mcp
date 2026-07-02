import { describe, expect, it } from 'vitest';

import type { StreamClient } from '../../src/client/http.js';
import { registerDocsTools } from '../../src/tools/docs/index.js';

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
  registerDocsTools(server, {} as StreamClient);
  const invoke = async (name: string, args: any) => {
    const tool = calls.find((t) => t.n === name);
    if (!tool) throw new Error(`tool not registered: ${name}`);
    return await tool.h(args, {} as any);
  };
  return { calls, invoke };
}

function parse(result: any): any {
  return JSON.parse(result.content[0].text);
}

describe('docs tools', () => {
  it('registers search_docs and get_doc', () => {
    const { calls } = setup();
    expect(calls.map((c) => c.n).sort()).toEqual(['get_doc', 'search_docs']);
  });

  it('search_docs ranks a relevant topic for a CA query', async () => {
    const { invoke } = setup();
    const out = parse(
      await invoke('search_docs', {
        query: 'create root CA from scratch',
        max_results: 3,
      }),
    );
    expect(out.count).toBeGreaterThan(0);
    expect(out.results.map((r: any) => r.uri)).toContain(
      'stream://knowledge/ca-management',
    );
    expect(out.results[0].snippet.length).toBeGreaterThan(0);
  });

  it('search_docs finds the query-languages topic for SCQL', async () => {
    const { invoke } = setup();
    const out = parse(
      await invoke('search_docs', {
        query: 'SCQL certificate search fields',
        max_results: 5,
      }),
    );
    expect(out.results.map((r: any) => r.uri)).toContain(
      'stream://knowledge/query-languages',
    );
  });

  it('get_doc returns full markdown by slug and by full URI', async () => {
    const { invoke } = setup();
    const bySlug = await invoke('get_doc', { uri: 'ca-management' });
    expect(bySlug.content[0].text).toContain('CA');
    expect(bySlug.content[0].text.length).toBeGreaterThan(200);
    const byUri = await invoke('get_doc', {
      uri: 'stream://knowledge/server-rules',
    });
    expect(byUri.content[0].text.length).toBeGreaterThan(100);
  });

  it('get_doc surfaces an unknown URI as an isError result with topics', async () => {
    const { invoke } = setup();
    const out = await invoke('get_doc', { uri: 'nope' });
    // A miss is a tool execution error, not content a model could trust.
    expect(out.isError).toBe(true);
    expect(out.content[0].text).toContain('Unknown doc URI');
    expect(out.content[0].text).toContain('stream://knowledge/');
  });
});
