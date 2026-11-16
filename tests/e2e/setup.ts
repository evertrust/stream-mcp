import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamClient } from '../../src/client/http.js';

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

interface LicenseInfo {
  readonly version: string;
  readonly modules: readonly string[];
}

let licensePromise: Promise<LicenseInfo | null> | undefined;

/**
 * The public license info (GET /api/v1/licenses) of the live instance, fetched
 * once. Null when STREAM_E2E_* is not set.
 */
export function getLiveLicense(): Promise<LicenseInfo | null> {
  licensePromise ??= (async () => {
    const url = process.env.STREAM_E2E_URL;
    const apiId = process.env.STREAM_E2E_API_ID;
    const apiKey = process.env.STREAM_E2E_API_KEY;
    if (!url || !apiId || !apiKey) return null;
    const client = new StreamClient(
      url,
      new LocalAccountAuthProvider(apiId, apiKey, 'local'),
      {
        timeout: 30,
        exportTimeout: 60,
        verifySsl: process.env.STREAM_E2E_TLS_INSECURE !== 'true',
      },
    );
    try {
      const info = await client.get<Partial<LicenseInfo>>('/api/v1/licenses');
      return { version: info.version ?? '', modules: info.modules ?? [] };
    } finally {
      await client.close();
    }
  })();
  return licensePromise;
}

/** True when the live instance reports Stream `major.minor` or later. */
export async function isStreamAtLeast(
  major: number,
  minor: number,
): Promise<boolean> {
  const license = await getLiveLicense();
  const m = license?.version.match(/^(\d+)\.(\d+)/);
  if (!m) return false;
  const [liveMajor, liveMinor] = [Number(m[1]), Number(m[2])];
  return liveMajor > major || (liveMajor === major && liveMinor >= minor);
}
