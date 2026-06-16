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
  },
});
