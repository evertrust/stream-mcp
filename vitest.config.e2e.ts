import { readFileSync } from 'node:fs';
import { defineConfig } from 'vitest/config';

/** Load `.md` imports as a string default export (matches tsup's loader). */
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
    include: ['tests/e2e/**/*.test.ts'],
    environment: 'node',
    setupFiles: ['tests/e2e/setup.ts'],
    testTimeout: 60000,
    hookTimeout: 60000,
    fileParallelism: false,
  },
});
