import { readFileSync } from 'node:fs';

import { defineConfig } from 'tsup';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8')) as {
  version: string;
};

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
  // Compile-time build metadata (see src/build-info.ts).
  define: {
    __STREAM_MCP_VERSION__: JSON.stringify(pkg.version),
    __STREAM_MCP_BUILD_TIME__: JSON.stringify(new Date().toISOString()),
  },
});
