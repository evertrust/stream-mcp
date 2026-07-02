import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { describe, expect, it } from 'vitest';

import type { StreamClient } from '../../src/client/http.js';
import { registerAllResources } from '../../src/resources/index.js';
import { registerAllTools } from '../../src/tools/registry.js';

async function bootAndListTools() {
  const server = new McpServer(
    { name: 'Stream MCP Server (test)', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  // The client is never invoked during tool *listing*, so a stub is fine.
  registerAllResources(server);
  registerAllTools(server, {} as StreamClient);

  const client = new Client({ name: 'test', version: '0.0.0' });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  const { tools } = await client.listTools();
  await client.close();
  return tools;
}

describe('server integration', () => {
  it('registers the full tool surface with unique names', async () => {
    const tools = await bootAndListTools();
    const names = tools.map((t) => t.name);
    const dupes = names.filter((n, i) => names.indexOf(n) !== i);
    expect(dupes).toEqual([]);
    // Exact tool count - a drift tripwire. When this changes, update the
    // documented totals in README.md and docs/tools-reference.md to match.
    expect(names.length).toBe(157);
  });

  it('exposes representative tools from every domain', async () => {
    const names = new Set((await bootAndListTools()).map((t) => t.name));
    for (const expected of [
      'list_cas',
      'create_ca',
      'issue_ca',
      'generate_ca_csr',
      'search_certificates',
      'enroll_certificate',
      'revoke_certificate',
      'list_templates',
      'list_crls',
      'create_ocsp_signer',
      'assign_ocsp_signer_to_ca',
      'list_keystores',
      'create_key',
      'get_hsm_info',
      'create_trigger',
      'test_trigger',
      'upsert_system_configuration',
      'get_license_info',
      'whoami',
      'create_role',
      'reset_local_identity_password',
      'search_events',
      'decode_x509',
      'extract_pkcs12',
      'list_ekus',
      'create_tsa_authority',
      'generate_tsa_signer_csr',
      'create_ssh_ca',
      'enroll_ssh_certificate',
      'generate_krl',
      'search_docs',
      'get_doc',
    ]) {
      expect(names, `missing tool: ${expected}`).toContain(expected);
    }
  });

  it('exposes the knowledge resources', async () => {
    const server = new McpServer(
      { name: 'Stream MCP Server (test)', version: '0.0.0' },
      { capabilities: { tools: {}, resources: {} } },
    );
    registerAllResources(server);
    registerAllTools(server, {} as StreamClient);
    const client = new Client({ name: 'test', version: '0.0.0' });
    const [clientT, serverT] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(serverT), client.connect(clientT)]);
    const { resources } = await client.listResources();
    await client.close();
    const uris = resources.map((r) => r.uri);
    expect(uris).toContain('stream://knowledge/server-rules');
    expect(uris).toContain('stream://knowledge/query-languages');
    expect(uris).toContain('stream://knowledge/ca-management');
    // 15 top-level knowledge topics (split-section sub-resources add more).
    const topLevel = uris.filter((u) =>
      /^stream:\/\/knowledge\/[^/]+$/.test(u),
    );
    expect(topLevel.length).toBe(15);
  });

  it('annotates read vs destructive tools correctly', async () => {
    const tools = await bootAndListTools();
    const byName = new Map(tools.map((t) => [t.name, t]));
    expect(byName.get('list_cas')?.annotations?.readOnlyHint).toBe(true);
    expect(byName.get('delete_ca')?.annotations?.destructiveHint).toBe(true);
    expect(byName.get('revoke_certificate')?.annotations?.destructiveHint).toBe(
      true,
    );
    expect(byName.get('update_template')?.annotations?.idempotentHint).toBe(
      true,
    );
    // HSM tools load a native library on the server -> not read-only, open-world.
    expect(byName.get('get_hsm_info')?.annotations?.readOnlyHint).toBe(false);
    expect(byName.get('get_hsm_info')?.annotations?.openWorldHint).toBe(true);
    expect(byName.get('get_hsm_slots')?.annotations?.readOnlyHint).toBe(false);
    // Integrity check kicks off a background job + persists a report -> not read-only.
    expect(
      byName.get('run_event_integrity_check')?.annotations?.readOnlyHint,
    ).toBe(false);
    expect(
      byName.get('run_event_integrity_check')?.annotations?.idempotentHint,
    ).toBe(false);
  });

  it('every tool description carries a Safety tier line', async () => {
    const tools = await bootAndListTools();
    const missing = tools
      .filter((t) => !(t.description ?? '').includes('Safety tier'))
      .map((t) => t.name);
    expect(missing).toEqual([]);
    const byName = new Map(tools.map((t) => [t.name, t]));
    // Auto-derived tiers for previously-unlabelled hand-written tools.
    expect(byName.get('search_certificates')?.description).toContain(
      'Safety tier: read-only',
    );
    expect(byName.get('revoke_certificate')?.description).toContain(
      'Safety tier: destructive',
    );
    expect(byName.get('enroll_certificate')?.description).toContain(
      'Safety tier: additive',
    );
    // The tier line is authoritative (derived from annotations): exactly one
    // occurrence per tool, and only the docs vocabulary appears.
    for (const t of tools) {
      const matches = (t.description ?? '').match(/Safety tier: ([^\n]*)/g);
      expect(matches?.length, t.name).toBe(1);
      expect(matches![0], t.name).toMatch(
        /^Safety tier: (read-only|idempotent|additive|destructive|open-world)$/,
      );
    }
  });

  it('scaffold CRUD tools declare structured output schemas', async () => {
    const tools = await bootAndListTools();
    const byName = new Map(tools.map((t) => [t.name, t]));
    for (const name of ['create_role', 'update_role', 'delete_role']) {
      const schema = byName.get(name)?.outputSchema as
        | { properties?: Record<string, unknown> }
        | undefined;
      expect(schema?.properties, `${name} missing outputSchema`).toBeDefined();
    }
    expect(
      (byName.get('create_role')?.outputSchema as { properties: object })
        .properties,
    ).toHaveProperty('status');
    expect(
      (byName.get('delete_role')?.outputSchema as { properties: object })
        .properties,
    ).toHaveProperty('deleted');
  });

  it('classifies prefix edge cases correctly', async () => {
    const tools = await bootAndListTools();
    const byName = new Map(tools.map((t) => [t.name, t]));
    const ann = (n: string) => byName.get(n)?.annotations;
    // generate_*_csr derives a CSR with no state change -> read-only.
    expect(ann('generate_ca_csr')?.readOnlyHint).toBe(true);
    // find_* is a read-only POST search.
    expect(ann('find_ca_keys')?.readOnlyHint).toBe(true);
    // assign_* converges -> idempotent mutation, not destructive.
    expect(ann('assign_ocsp_signer_to_ca')?.idempotentHint).toBe(true);
    expect(ann('assign_ocsp_signer_to_ca')?.destructiveHint).toBe(false);
    // migrate_* is one-way (repeat -> error) -> additive, NOT idempotent.
    expect(ann('migrate_ca')?.idempotentHint).toBe(false);
    expect(ann('migrate_ca')?.readOnlyHint).toBe(false);
    // reset_* irreversibly replaces the old secret -> destructive, NOT idempotent.
    expect(ann('reset_local_identity_password')?.idempotentHint).toBe(false);
    expect(ann('reset_local_identity_password')?.destructiveHint).toBe(true);
    // enroll_* creates a new certificate -> additive, not read-only. It talks
    // to the closed Stream API only -> NOT open-world (per MCP spec semantics).
    expect(ann('enroll_certificate')?.readOnlyHint).toBe(false);
    expect(ann('enroll_certificate')?.openWorldHint).toBe(false);
    // test_trigger REST mode makes Stream call an arbitrary external URL.
    expect(ann('test_trigger')?.openWorldHint).toBe(true);
  });
});
