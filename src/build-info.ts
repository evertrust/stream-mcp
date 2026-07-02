/**
 * Build metadata resolution.
 *
 * `__STREAM_MCP_VERSION__` / `__STREAM_MCP_BUILD_TIME__` are compile-time
 * constants injected by tsup (see tsup.config.ts `define`). In dev (tsx) they
 * are not defined, so we fall back to reading package.json next to the source
 * tree; compiled single-binary builds cannot read package.json, which is why
 * the define is the primary source.
 */
import { createRequire } from 'node:module';

declare const __STREAM_MCP_VERSION__: string | undefined;
declare const __STREAM_MCP_BUILD_TIME__: string | undefined;

function readPackageVersion(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    // Both src/ (dev) and dist/ (published) sit one level below package.json.
    const pkg = require('../package.json') as { version?: string };
    return pkg.version;
  } catch {
    return undefined;
  }
}

/** The package version, resolved at build time (fallback: package.json). */
export const VERSION: string =
  (typeof __STREAM_MCP_VERSION__ === 'string'
    ? __STREAM_MCP_VERSION__
    : undefined) ??
  readPackageVersion() ??
  '0.0.0-dev';

/**
 * Build timestamp for bundled assets (knowledge markdown). Falls back to
 * process start in dev, where sources may be newer than any build.
 */
export const BUILD_TIMESTAMP_ISO: string =
  (typeof __STREAM_MCP_BUILD_TIME__ === 'string'
    ? __STREAM_MCP_BUILD_TIME__
    : undefined) ?? new Date().toISOString();
