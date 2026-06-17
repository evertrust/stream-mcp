import { describe, expect, it } from 'vitest';

import { loadScenarioMetadata, rankTools } from './setup.js';

/**
 * Free, deterministic smoke tests (no model, no network). These assert the tool
 * surface is coherent and that a simple keyword ranker — a cheap proxy for a
 * small model's tool choice — picks sensible tools for representative prompts.
 */
describe('Stream MCP scenario smoke (deterministic)', () => {
  it('exposes a coherent tool + resource surface', async () => {
    const { tools, resources } = await loadScenarioMetadata();

    // 151 domain tools + describe_ca_schema + search_docs/get_doc.
    expect(tools.length).toBeGreaterThanOrEqual(150);
    expect(resources.length).toBeGreaterThanOrEqual(15);

    // Every tool is documented and carries a read-only-ness annotation.
    for (const t of tools) {
      expect(t.name, `tool name`).toMatch(/^[a-z][a-z0-9_]+$/);
      expect(
        (t.description ?? '').length,
        `${t.name} description`,
      ).toBeGreaterThan(10);
      expect(
        typeof t.annotations?.['readOnlyHint'],
        `${t.name} readOnlyHint annotation`,
      ).toBe('boolean');
    }

    const names = new Set(tools.map((t) => t.name));
    for (const expected of [
      'whoami',
      'list_cas',
      'create_ca',
      'search_certificates',
      'revoke_certificate',
      'decode_x509',
      'search_docs',
    ]) {
      expect(names, `missing ${expected}`).toContain(expected);
    }
  });

  it('ranks whoami first for an identity question', async () => {
    const ranked = await rankTools(
      'Who am I and what roles and permissions do I have?',
    );
    expect(ranked[0]?.item.name).toBe('whoami');
  });

  it('prefers aggregate over search for a grouped-count question', async () => {
    const ranked = await rankTools(
      'How many certificates are there grouped by template?',
    );
    const agg = ranked.findIndex(
      (r) => r.item.name === 'aggregate_certificates',
    );
    const search = ranked.findIndex(
      (r) => r.item.name === 'search_certificates',
    );
    expect(agg).toBeGreaterThanOrEqual(0);
    expect(search).toBeGreaterThanOrEqual(0);
    expect(agg).toBeLessThan(search);
  });

  it('ranks decode_x509 highly for a decode request', async () => {
    const ranked = await rankTools('Decode this X509 certificate PEM for me.');
    const idx = ranked.findIndex((r) => r.item.name === 'decode_x509');
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(idx).toBeLessThan(5);
  });

  it('ranks search_certificates highly for a certificate search', async () => {
    const ranked = await rankTools(
      'Search certificates where the dn contains acme.',
    );
    const idx = ranked.findIndex((r) => r.item.name === 'search_certificates');
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(idx).toBeLessThan(5);
  });
});
