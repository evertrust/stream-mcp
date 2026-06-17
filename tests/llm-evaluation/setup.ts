/**
 * Shared harness for the free, deterministic LLM-evaluation tier.
 *
 * - loadScenarioMetadata(): boot the Stream MCP in-process with a MOCK client
 *   and list its tools/resources (no network, no model).
 * - rankTools(): a lightweight keyword ranker used as a $0 proxy for "would a
 *   small model pick the right tool for this prompt".
 * - connectGrounded(): boot the MCP with a REAL StreamClient (from STREAM_E2E_*)
 *   so tests can call tools and assert the MCP returns USABLE output. Gated.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamClient } from '../../src/client/http.js';
import { registerAllResources } from '../../src/resources/index.js';
import { registerAllTools } from '../../src/tools/registry.js';

export const E2E_CONFIGURED =
  Boolean(process.env['STREAM_E2E_URL']) &&
  Boolean(process.env['STREAM_E2E_API_ID']) &&
  Boolean(process.env['STREAM_E2E_API_KEY']);

export interface ListedTool {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: Record<string, unknown>;
  readonly annotations?: Record<string, unknown>;
}

export interface ListedResource {
  readonly uri: string;
  readonly description?: string;
}

type ScenarioMetadata = {
  readonly tools: ListedTool[];
  readonly resources: ListedResource[];
};

/** Minimal StreamClient stand-in — handlers are not invoked during listing. */
function createMockClient(): unknown {
  return {
    get: async () => ({}),
    getList: async () => [],
    post: async () => ({}),
    put: async () => ({}),
    patch: async () => ({}),
    delete: async () => null,
    getBytes: async () => new ArrayBuffer(0),
    getText: async () => '',
    postMultipart: async () => ({}),
    close: async () => {},
    exportTimeout: 120000,
    principalName: undefined,
    streamVersion: undefined,
  };
}

async function bootClient(client: unknown): Promise<Client> {
  const server = new McpServer(
    { name: 'scenario-eval', version: '0.0.0' },
    { capabilities: { tools: {}, resources: {} } },
  );
  registerAllResources(server);
  registerAllTools(server, client as Parameters<typeof registerAllTools>[1]);

  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const mcpClient = new Client({
    name: 'scenario-eval-client',
    version: '0.0.0',
  });
  await Promise.all([
    mcpClient.connect(clientTransport),
    server.connect(serverTransport),
  ]);
  return mcpClient;
}

let metadataPromise: Promise<ScenarioMetadata> | undefined;

export async function loadScenarioMetadata(): Promise<ScenarioMetadata> {
  if (metadataPromise) return metadataPromise;
  metadataPromise = (async () => {
    const client = await bootClient(createMockClient());
    const [toolResult, resourceResult] = await Promise.all([
      client.listTools(),
      client.listResources(),
    ]);
    await client.close();
    return {
      tools: toolResult.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema as Record<string, unknown> | undefined,
        annotations: t.annotations as Record<string, unknown> | undefined,
      })),
      resources: resourceResult.resources.map((r) => ({
        uri: r.uri,
        description: r.description,
      })),
    };
  })();
  return metadataPromise;
}

/**
 * Boot the MCP with a REAL StreamClient against the QA instance. Caller must
 * `await client.close()`. Throws if STREAM_E2E_* is not configured.
 */
export async function connectGrounded(): Promise<Client> {
  if (!E2E_CONFIGURED) {
    throw new Error(
      'connectGrounded requires STREAM_E2E_* (source .env.local).',
    );
  }
  const real = new StreamClient(
    process.env['STREAM_E2E_URL']!,
    new LocalAccountAuthProvider(
      process.env['STREAM_E2E_API_ID']!,
      process.env['STREAM_E2E_API_KEY']!,
      process.env['STREAM_E2E_API_IDPROV'] ?? 'local',
    ),
    { timeout: 30, exportTimeout: 120, verifySsl: true },
  );
  return bootClient(real);
}

/** Parse the text content of a tool result into JSON (or return the raw text). */
export function toolJson(result: {
  content?: Array<{ type: string; text?: string }>;
}): unknown {
  const txt = result.content?.find((c) => c.type === 'text')?.text ?? '';
  try {
    return JSON.parse(txt);
  } catch {
    return txt;
  }
}

// ---------------------------------------------------------------------------
// Lightweight keyword ranker (deterministic $0 tool-selection proxy)
// ---------------------------------------------------------------------------

const STOPWORDS = new Set([
  'a',
  'an',
  'and',
  'are',
  'as',
  'at',
  'by',
  'do',
  'for',
  'from',
  'how',
  'i',
  'in',
  'is',
  'it',
  'me',
  'my',
  'of',
  'on',
  'or',
  'show',
  'the',
  'to',
  'use',
  'using',
  'what',
  'with',
  'all',
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[_:/().-]+/g, ' ')
    .split(/\s+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 1 && !STOPWORDS.has(t));
}

function keywordBonus(question: string, candidate: string): number {
  let score = 0;
  const q = question.toLowerCase();
  // certificate search vs aggregate
  if (
    /(count|how many|group|grouped|distribution|breakdown|by )/.test(q) &&
    candidate.includes('aggregate_')
  )
    score += 30;
  if (
    /(count|how many|group|grouped|distribution|breakdown)/.test(q) &&
    candidate.includes('search_')
  )
    score -= 10;
  // decoders
  if (/decode|parse|inspect/.test(q) && candidate.startsWith('decode_'))
    score += 16;
  // who am I
  if (
    /(who am i|my permissions|my roles|am i)/.test(q) &&
    candidate === 'whoami'
  )
    score += 30;
  // knowledge
  if (
    /(how do i|how to|guide|documentation|docs|workflow)/.test(q) &&
    candidate === 'search_docs'
  )
    score += 20;
  // CA create-from-scratch
  if (
    /(create|stand up|set up|new).*(ca|certificate authority|authority)/.test(
      q,
    ) &&
    candidate === 'create_ca'
  )
    score += 18;
  return score;
}

function overlap(qTokens: string[], hay: string): number {
  let s = 0;
  for (const t of qTokens) {
    if (!hay.includes(t)) continue;
    s += t.length >= 7 ? 5 : t.length >= 5 ? 4 : 2;
  }
  return s;
}

export async function rankTools(
  question: string,
): Promise<Array<{ item: ListedTool; score: number }>> {
  const { tools } = await loadScenarioMetadata();
  const qTokens = tokenize(question);
  return tools
    .map((item) => {
      const hay = `${item.name} ${item.description ?? ''}`.toLowerCase();
      return {
        item,
        score: overlap(qTokens, hay) + keywordBonus(question, item.name),
      };
    })
    .sort((a, b) => b.score - a.score);
}
