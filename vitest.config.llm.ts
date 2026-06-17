import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

/**
 * Free, deterministic LLM-evaluation tier: in-process MCP metadata + tool
 * ranking + (when STREAM_E2E_* is set) grounded tool-output checks. No external
 * model is called, so this runs anywhere.
 */
function markdownAsText() {
  return {
    name: 'md-as-text',
    enforce: 'pre' as const,
    transform(_code: string, id: string) {
      if (!id.endsWith('.md')) return null;
      return { code: `export default ${JSON.stringify(readFileSync(id, 'utf-8'))};`, map: null };
    },
  };
}

export default defineConfig({
  plugins: [markdownAsText()],
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/llm-evaluation/**/*.test.ts'],
    setupFiles: ['tests/e2e/setup.ts'],
    testTimeout: 180_000,
    fileParallelism: false,
  },
});
