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
    // 151 domain tools (+ any describe_*_schema helpers for polymorphic objects).
    expect(names.length).toBeGreaterThanOrEqual(151);
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
  });
});
