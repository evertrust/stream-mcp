/**
 * Drive the Claude Agent SDK against a real, spawned Stream MCP server to verify
 * a small model (default Sonnet) can both SELECT the right tool and surface a
 * USABLE answer from this MCP's tools.
 *
 * The SDK spawns the bundled `claude` binary, attaches the Stream MCP over stdio
 * (bun run src/index.ts), runs the agent loop, and streams messages back. We
 * collect the tool calls and the final assistant text.
 */
import {
  type Options,
  type SDKMessage,
  query,
} from '@anthropic-ai/claude-agent-sdk';
import path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const STREAM_MCP_ENTRY = path.join(REPO_ROOT, 'src', 'index.ts');
const MCP_TOOL_PREFIX = 'mcp__stream__';

export const DEFAULT_LIVE_MODEL =
  process.env['STREAM_LLM_LIVE_MODEL'] ?? 'claude-sonnet-4-5';

export interface ScenarioRunResult {
  readonly toolCalls: readonly string[];
  readonly allToolCalls: readonly string[];
  readonly toolInputs: ReadonlyMap<string, Record<string, unknown>>;
  readonly turns: number;
  readonly totalCostUsd: number;
  readonly stopReason: string | null;
  readonly assistantText: string;
  readonly errors: readonly string[];
}

export interface RunScenarioOptions {
  readonly model?: string;
  readonly maxTurns?: number;
  readonly maxBudgetUsd?: number;
}

function buildMcpEnv(): Record<string, string> {
  const required = [
    'STREAM_E2E_URL',
    'STREAM_E2E_API_ID',
    'STREAM_E2E_API_KEY',
  ];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length > 0) {
    throw new Error(
      `Live LLM suite requires QA credentials: ${missing.join(', ')}. Source .env.local first.`,
    );
  }
  return {
    STREAM_URL: process.env['STREAM_E2E_URL']!,
    STREAM_API_ID: process.env['STREAM_E2E_API_ID']!,
    STREAM_API_KEY: process.env['STREAM_E2E_API_KEY']!,
    STREAM_API_IDPROV: process.env['STREAM_E2E_API_IDPROV'] ?? 'local',
    STREAM_LOG_LEVEL: process.env['STREAM_LOG_LEVEL'] ?? 'warning',
  };
}

function stripMcpPrefix(name: string): string {
  return name.startsWith(MCP_TOOL_PREFIX)
    ? name.slice(MCP_TOOL_PREFIX.length)
    : name;
}

export async function runScenarioWithClaude(
  prompt: string,
  options: RunScenarioOptions = {},
): Promise<ScenarioRunResult> {
  const toolCalls: string[] = [];
  const allToolCalls: string[] = [];
  const toolInputs = new Map<string, Record<string, unknown>>();
  const assistantTextChunks: string[] = [];
  const errors: string[] = [];
  let turns = 0;
  let totalCostUsd = 0;
  let stopReason: string | null = null;

  const sdkOptions: Options = {
    model: options.model ?? DEFAULT_LIVE_MODEL,
    // The server exposes 150+ tools that Claude Code defers behind ToolSearch,
    // so the model spends a turn discovering MCP tools before calling one.
    maxTurns: options.maxTurns ?? 8,
    maxBudgetUsd: options.maxBudgetUsd ?? 0.6,
    permissionMode: 'bypassPermissions',
    allowDangerouslySkipPermissions: true,
    mcpServers: {
      stream: {
        command: 'bun',
        args: ['run', STREAM_MCP_ENTRY],
        env: buildMcpEnv(),
      },
    },
  };

  const q = query({ prompt, options: sdkOptions });
  try {
    for await (const msg of q as AsyncIterable<SDKMessage>) {
      if (msg.type === 'assistant' && msg.message?.content) {
        if (msg.error) errors.push(`assistant_error:${msg.error}`);
        for (const block of msg.message.content) {
          if (block.type === 'tool_use') {
            const isMcp = block.name.startsWith(MCP_TOOL_PREFIX);
            const display = stripMcpPrefix(block.name);
            allToolCalls.push(isMcp ? display : `<builtin:${display}>`);
            if (isMcp) {
              toolCalls.push(display);
              toolInputs.set(
                display,
                (block.input ?? {}) as Record<string, unknown>,
              );
            }
          } else if (block.type === 'text') {
            assistantTextChunks.push(block.text);
          }
        }
      } else if (msg.type === 'result') {
        turns = msg.num_turns;
        totalCostUsd = msg.total_cost_usd;
        stopReason = msg.stop_reason;
        if (msg.subtype === 'error_max_budget_usd')
          errors.push('budget_exceeded');
        break;
      }
    }
  } finally {
    q.close();
  }

  return {
    toolCalls,
    allToolCalls,
    toolInputs,
    turns,
    totalCostUsd,
    stopReason,
    assistantText: assistantTextChunks.join('\n'),
    errors,
  };
}
