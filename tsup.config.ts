import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  // Matches package.json engines.node (>=22.19, the real undici floor).
  target: 'node22',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  // Inline knowledge markdown files as string constants.
  // Plain imports (import x from "./file.md") work with this loader.
  loader: { '.md': 'text' },
});
