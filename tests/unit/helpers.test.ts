/**
 * Response-envelope hardening: every read path (list, search) must apply the
 * shared secret redaction, and list responses must truncate oversized fields
 * the same way search responses do.
 */
import { describe, expect, it } from 'vitest';

import {
  buildListResponse,
  buildSearchResponse,
} from '../../src/tools/helpers.js';

describe('buildSearchResponse', () => {
  it('redacts secret-bearing fields in search results', () => {
    const result = buildSearchResponse(
      {
        results: [
          { name: 'a', password: 'hunter2', nested: { pin: '1234' } },
          { name: 'b', secret: 's3cr3t' },
        ],
      },
      1,
      20,
    );
    const records = result['results'] as Record<string, unknown>[];
    expect(JSON.stringify(records)).not.toContain('hunter2');
    expect(JSON.stringify(records)).not.toContain('s3cr3t');
    expect(JSON.stringify(records)).not.toContain('1234');
    // Non-secret fields survive.
    expect(records[0]!['name']).toBe('a');
  });

  it('still truncates oversized values after redaction', () => {
    const long = 'x'.repeat(2000);
    const result = buildSearchResponse({ results: [{ blob: long }] }, 1, 20);
    const records = result['results'] as Record<string, unknown>[];
    expect(String(records[0]!['blob'])).toContain('<truncated');
  });
});

describe('buildListResponse', () => {
  it('truncates oversized string fields in list items', () => {
    const long = 'y'.repeat(2000);
    const out = JSON.parse(
      buildListResponse([{ name: 'a', blob: long }], 50, 'thing'),
    );
    expect(String(out.items[0].blob)).toContain('<truncated');
    expect(out.items[0].name).toBe('a');
  });

  it('keeps redacting secret fields', () => {
    const out = JSON.parse(
      buildListResponse([{ name: 'a', password: 'hunter2' }], 50, 'thing'),
    );
    expect(JSON.stringify(out)).not.toContain('hunter2');
  });
});
