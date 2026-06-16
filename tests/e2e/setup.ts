import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Load `.env.local` into process.env for live e2e tests.
 * The file uses `export KEY="value"` lines (shell-sourceable); we parse the
 * KEY=value pairs and strip surrounding quotes. Missing file is non-fatal —
 * the e2e tests themselves skip when STREAM_E2E_* is absent.
 */
function loadDotEnvLocal(): void {
  let raw: string;
  try {
    raw = readFileSync(resolve(process.cwd(), '.env.local'), 'utf-8');
  } catch {
    return;
  }
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const m = trimmed.replace(/^export\s+/, '').match(/^([A-Z0-9_]+)=(.*)$/);
    if (!m) continue;
    const key = m[1]!;
    let value = m[2]!.trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

loadDotEnvLocal();
