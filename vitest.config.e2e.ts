import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/e2e/**/*.test.ts'],
    environment: 'node',
    setupFiles: ['tests/e2e/setup.ts'],
    // Live calls against a real QA instance can be slow; allow generous timeouts.
    testTimeout: 60000,
    hookTimeout: 60000,
    // Avoid cross-test interference when mutating shared QA state.
    fileParallelism: false,
  },
});
