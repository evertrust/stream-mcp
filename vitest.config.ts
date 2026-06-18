import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

/**
 * Load `.md` imports as a string default export, matching tsup's
 * `loader: { '.md': 'text' }` so the resource catalog imports resolve in tests.
 */
function markdownAsText() {
  return {
    name: 'md-as-text',
    enforce: 'pre' as const,
    transform(_code: string, id: string) {
      if (!id.endsWith('.md')) return null;
      const text = readFileSync(id, 'utf-8');
      return { code: `export default ${JSON.stringify(text)};`, map: null };
    },
  };
}

export default defineConfig({
  plugins: [markdownAsText()],
  test: {
    include: ['tests/unit/**/*.test.ts'],
    environment: 'node',
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // Generated artifacts, pure enum/constant tables, and the stdio bootstrap
      // (exercised by e2e, not unit) are excluded from the unit-coverage gate.
      exclude: ['src/generated/**', 'src/**/enums.ts', 'src/index.ts'],
      reporter: ['text-summary', 'lcov'],
      // Floors set just below the current measured baseline (statements ~88,
      // branches ~73, functions ~91, lines ~90) so the gate catches regressions
      // today; ratchet upward toward 80%+ branches as coverage improves.
      thresholds: {
        statements: 85,
        branches: 70,
        functions: 85,
        lines: 85,
      },
    },
  },
});
