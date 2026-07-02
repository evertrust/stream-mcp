/**
 * Doc-truth: every tool call shown in the knowledge base must match the
 * registered tool surface.
 *
 * verify-truth.ts guards the HTTP routes against the Stream backend source;
 * this suite guards the OTHER truth boundary - the knowledge markdown the
 * model reads first. It extracts call-shaped examples (`tool_name(param=...)`)
 * and bare backticked tool mentions from src/resources/knowledge/*.md and
 * asserts:
 *   1. the tool exists in the registry,
 *   2. every named parameter exists in the tool's input schema,
 *   3. all schema-required parameters appear in the example (unless the
 *      example is elided with `...`).
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { beforeAll, describe, expect, it } from 'vitest';

import type { StreamClient } from '../../src/client/http.js';
import { registerAllTools } from '../../src/tools/registry.js';

const KNOWLEDGE_DIR = join(__dirname, '../../src/resources/knowledge');

// Verb prefixes that make a bare backticked identifier a tool reference.
const TOOL_VERB_RE =
  /^(list|get|create|update|delete|search|aggregate|enroll|revoke|decode|describe|detect|extract|upsert|generate|assign|reset|migrate|enhance|issue|upload|find|export)_[a-z0-9_]+$/;

// Backticked snake_case identifiers that legitimately are NOT tool names
// (parameter names, wire fields, env vars in prose). Add here ONLY with a
// reason - anything else that looks like a tool must exist in the registry.
const NON_TOOL_ALLOWLIST = new Set<string>([
  // revocation.md explicitly documents that this tool does NOT exist (external
  // CRL storage is a trigger type) - a deliberate negative mention.
  'create_external_crl_storage',
]);

interface ToolInfo {
  readonly params: Set<string>;
  readonly required: Set<string>;
}

let tools: Map<string, ToolInfo>;

beforeAll(async () => {
  const server = new McpServer(
    { name: 'doc-truth (test)', version: '0.0.0' },
    { capabilities: { tools: {} } },
  );
  registerAllTools(server, {} as StreamClient);
  const client = new Client({ name: 'test', version: '0.0.0' });
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  const listed = await client.listTools();
  await client.close();

  tools = new Map(
    listed.tools.map((t) => {
      const schema = t.inputSchema as {
        properties?: Record<string, unknown>;
        required?: string[];
      };
      return [
        t.name,
        {
          params: new Set(Object.keys(schema.properties ?? {})),
          required: new Set(schema.required ?? []),
        },
      ];
    }),
  );
});

interface CallExample {
  readonly file: string;
  readonly tool: string;
  readonly args: string;
}

function knowledgeFiles(): string[] {
  return readdirSync(KNOWLEDGE_DIR).filter((f) => f.endsWith('.md'));
}

/** Extract `tool_name(...)` call examples (multi-line aware). */
function extractCalls(file: string, content: string): CallExample[] {
  const calls: CallExample[] = [];
  // Callee must be snake_case with at least one underscore; args must not
  // contain parentheses (none of the knowledge examples nest them).
  const re = /\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\(([^()]*)\)/g;
  for (const match of content.matchAll(re)) {
    calls.push({ file, tool: match[1]!, args: match[2]! });
  }
  return calls;
}

/** Extract named parameters (`foo=` at top level) from an argument string. */
function extractParamNames(args: string): string[] {
  const names: string[] = [];
  for (const m of args.matchAll(/(?:^|,)\s*([a-z_][a-z0-9_]*)\s*=/g)) {
    names.push(m[1]!);
  }
  return names;
}

describe('knowledge docs match the registered tool surface', () => {
  it('has a populated registry to check against', () => {
    expect(tools.size).toBeGreaterThan(100);
  });

  it('every call-shaped example uses a real tool with real parameters', () => {
    const problems: string[] = [];
    for (const file of knowledgeFiles()) {
      const content = readFileSync(join(KNOWLEDGE_DIR, file), 'utf8');
      for (const call of extractCalls(file, content)) {
        const info = tools.get(call.tool);
        if (!info) {
          // Call-shaped snake_case identifiers that are not tools (e.g. wire
          // functions in backend prose) are only a problem if they LOOK like
          // tool references.
          if (TOOL_VERB_RE.test(call.tool) || call.tool === 'whoami') {
            problems.push(`${call.file}: unknown tool \`${call.tool}(...)\``);
          }
          continue;
        }
        const elided = call.args.includes('...');
        const named = extractParamNames(call.args);
        for (const param of named) {
          if (!info.params.has(param)) {
            problems.push(
              `${call.file}: \`${call.tool}\` has no parameter \`${param}\` ` +
                `(valid: ${[...info.params].join(', ')})`,
            );
          }
        }
        // Required-parameter completeness only when the example is fully
        // written out with named args (not elided, not positional prose).
        if (!elided && named.length > 0) {
          for (const req of info.required) {
            if (!named.includes(req)) {
              problems.push(
                `${call.file}: \`${call.tool}\` example omits required ` +
                  `parameter \`${req}\``,
              );
            }
          }
        }
      }
    }
    expect(problems, problems.join('\n')).toEqual([]);
  });

  it('every backticked tool-looking mention names a real tool', () => {
    const problems: string[] = [];
    for (const file of knowledgeFiles()) {
      const content = readFileSync(join(KNOWLEDGE_DIR, file), 'utf8');
      for (const m of content.matchAll(/`([a-z][a-z0-9_]+)`/g)) {
        const name = m[1]!;
        if (!TOOL_VERB_RE.test(name) && name !== 'whoami') continue;
        if (NON_TOOL_ALLOWLIST.has(name)) continue;
        if (!tools.has(name)) {
          problems.push(`${file}: mentions unknown tool \`${name}\``);
        }
      }
    }
    expect(problems, problems.join('\n')).toEqual([]);
  });
});
