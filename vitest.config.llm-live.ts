import { defineConfig } from 'vitest/config';

/**
 * Paid, model-driven LLM smoke tier: drives a real (small) Claude model via the
 * Claude Agent SDK against the spawned Stream MCP. COSTS MONEY.
 *
 * Deliberately has NO setupFiles: it must NOT auto-load .env.local, so the
 * suite cannot run (and bill) by accident. To run it you must BOTH source the
 * credentials AND opt in explicitly:
 *
 *   source .env.local && STREAM_LLM_LIVE=1 bun run test:llm:live
 *
 * Never run in CI or by default.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/llm-live/**/*.test.ts'],
    testTimeout: 300_000,
    hookTimeout: 60_000,
    fileParallelism: false,
  },
});
