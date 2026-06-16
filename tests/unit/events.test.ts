import { describe, expect, it, vi } from 'vitest';

import { registerEventTools } from '../../src/tools/events/index.js';

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
  registerEventTools(server, client);
  const tool = (name: string) => {
    const c = calls.find((x) => x.n === name);
    if (!c) throw new Error(`tool ${name} not registered`);
    return c;
  };
  return { calls, server, client, tool };
}

const lastText = (res: any): string => res.content[0].text;

const ID = '67f510b07a10ba4bcca47498';

describe('events registration', () => {
  it('registers exactly the 5 domain tools', () => {
    const { calls } = setup();
    const names = calls.map((c) => c.n).sort();
    expect(names).toEqual(
      [
        'get_event',
        'get_event_dictionary',
        'list_event_integrity_reports',
        'run_event_integrity_check',
        'search_events',
      ].sort(),
    );
  });
});

describe('search_events', () => {
  it('omits query (server match-all) when none is provided', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({
      results: [{ id: 'a', code: 'SERVICE-START' }],
      pageIndex: 1,
      pageSize: 20,
      hasMore: false,
    });
    const res = await tool('search_events').h({});
    expect(client.post).toHaveBeenCalledWith('/api/v1/events/search', {
      pageIndex: 1,
      pageSize: 20,
    });
    const payload = client.post.mock.calls[0][1];
    expect(payload).not.toHaveProperty('query');
    const body = JSON.parse(lastText(res));
    expect(body.results).toEqual([{ id: 'a', code: 'SERVICE-START' }]);
    expect(body.page_index).toBe(1);
    expect(res.structuredContent.page_index).toBe(1);
  });

  it('passes through query, paging, sortedBy (case-sensitive order), count', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ results: [], count: 0 });
    await tool('search_events').h({
      query: 'module equals service and status equals success',
      page_index: 2,
      page_size: 50,
      sorted_by: [{ element: 'timestamp', order: 'Desc' }],
      with_count: true,
    });
    expect(client.post).toHaveBeenCalledWith('/api/v1/events/search', {
      query: 'module equals service and status equals success',
      pageIndex: 2,
      pageSize: 50,
      sortedBy: [{ element: 'timestamp', order: 'Desc' }],
      withCount: true,
    });
  });

  it('caps page_size at 100', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ results: [] });
    await tool('search_events').h({ page_size: 500 });
    const payload = client.post.mock.calls[0][1];
    expect(payload.pageSize).toBe(100);
  });

  it('omits sortedBy and withCount when not provided', async () => {
    const { client, tool } = setup();
    client.post.mockResolvedValue({ results: [] });
    await tool('search_events').h({ query: 'code equals SERVICE-START' });
    const payload = client.post.mock.calls[0][1];
    expect(payload).not.toHaveProperty('sortedBy');
    expect(payload).not.toHaveProperty('withCount');
  });

  it('rejects an invalid sort element via the input schema enum', () => {
    const { tool } = setup();
    const schema = tool('search_events').c.inputSchema;
    const parsed = schema.safeParse({
      sorted_by: [{ element: 'seal', order: 'Asc' }],
    });
    expect(parsed.success).toBe(false);
  });
});

describe('get_event', () => {
  it('GETs the event by id', async () => {
    const { client, tool } = setup();
    client.get.mockResolvedValue({ id: ID, code: 'SERVICE-START' });
    const res = await tool('get_event').h({ id: ID });
    expect(client.get).toHaveBeenCalledWith(`/api/v1/events/${ID}`);
    expect(JSON.parse(lastText(res)).id).toBe(ID);
  });

  it('rejects a non-ObjectId id without calling the client', async () => {
    const { client, tool } = setup();
    const res = await tool('get_event').h({ id: 'not-an-objectid' });
    expect(client.get).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
  });
});

describe('get_event_dictionary', () => {
  it('GETs the dictionary endpoint', async () => {
    const { client, tool } = setup();
    client.get.mockResolvedValue({
      modules: ['service'],
      codes: ['SERVICE-START'],
      details: ['message'],
    });
    const res = await tool('get_event_dictionary').h({});
    expect(client.get).toHaveBeenCalledWith('/api/v1/events/search/dictionary');
    expect(JSON.parse(lastText(res)).modules).toEqual(['service']);
  });
});

describe('run_event_integrity_check', () => {
  it('GETs /integrity/run with no params when start_from omitted', async () => {
    const { client, tool } = setup();
    client.get.mockResolvedValue(null);
    const res = await tool('run_event_integrity_check').h({});
    expect(client.get).toHaveBeenCalledWith(
      '/api/v1/events/integrity/run',
      undefined,
    );
    expect(JSON.parse(lastText(res)).status).toBe('triggered');
  });

  it('passes start_from as the startFrom query param', async () => {
    const { client, tool } = setup();
    client.get.mockResolvedValue(null);
    await tool('run_event_integrity_check').h({ start_from: ID });
    const [path, params] = client.get.mock.calls[0];
    expect(path).toBe('/api/v1/events/integrity/run');
    expect(params).toBeInstanceOf(URLSearchParams);
    expect(params.toString()).toBe(`startFrom=${ID}`);
  });

  it('rejects a non-ObjectId start_from without calling the client', async () => {
    const { client, tool } = setup();
    const res = await tool('run_event_integrity_check').h({
      start_from: 'bad',
    });
    expect(client.get).not.toHaveBeenCalled();
    expect(res.isError).toBe(true);
  });
});

describe('list_event_integrity_reports', () => {
  it('uses getList against /events/integrity (204 -> [])', async () => {
    const { client, tool } = setup();
    client.getList.mockResolvedValue([]);
    const res = await tool('list_event_integrity_reports').h({});
    expect(client.getList).toHaveBeenCalledWith('/api/v1/events/integrity');
    const body = JSON.parse(lastText(res));
    expect(body.items).toEqual([]);
    expect(body.kind).toBe('event_integrity_report');
  });

  it('returns the reports list', async () => {
    const { client, tool } = setup();
    client.getList.mockResolvedValue([
      { id: '689601f10f3af216e5558a9c', status: 'eventIntegrityFailure' },
    ]);
    const res = await tool('list_event_integrity_reports').h({});
    const body = JSON.parse(lastText(res));
    expect(body.count).toBe(1);
    expect(body.items[0].status).toBe('eventIntegrityFailure');
  });
});
