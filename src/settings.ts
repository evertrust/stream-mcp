import { z } from 'zod';

const settingsSchema = z.object({
  url: z.string().default('https://localhost'),
  apiId: z.string().default(''),
  apiKey: z.string().default(''),
  apiIdprov: z.string().default('local'),
  clientCert: z.string().default(''),
  clientKey: z.string().default(''),
  clientKeyPassword: z.string().default(''),
  clientPfx: z.string().default(''),
  clientPfxPassword: z.string().default(''),
  verifySsl: z
    .string()
    .default('true')
    .transform((v) => v.toLowerCase() !== 'false' && v !== '0'),
  timeout: z.coerce.number().int().positive().default(30),
  exportTimeout: z.coerce.number().int().positive().default(120),
  logLevel: z.string().default('INFO'),
  testedVersions: z.array(z.string()).default(['2.1']),
  warnVersions: z.array(z.string()).default(['2.0', '2.2']),
});

export type StreamSettings = z.infer<typeof settingsSchema>;

/**
 * Convert SCREAMING_SNAKE_CASE to camelCase.
 * e.g. "CLIENT_PFX_PASSWORD" -> "clientPfxPassword"
 */
function snakeToCamel(key: string): string {
  return key
    .toLowerCase()
    .replace(/_([a-z])/g, (_, char: string) => char.toUpperCase());
}

/**
 * Read STREAM_* environment variables and parse into validated settings.
 * Strips the STREAM_ prefix and converts SCREAMING_SNAKE to camelCase.
 * STREAM_E2E_* (test-only) variables are intentionally ignored.
 */
export function loadSettings(
  env: Record<string, string | undefined> = process.env,
): StreamSettings {
  const prefix = 'STREAM_';
  const raw: Record<string, string> = {};

  for (const [key, value] of Object.entries(env)) {
    if (!key.startsWith(prefix) || value === undefined) continue;
    const stripped = key.slice(prefix.length);
    // Never feed test-only STREAM_E2E_* vars into the server settings.
    if (stripped.startsWith('E2E_')) continue;
    raw[snakeToCamel(stripped)] = value;
  }

  const result = settingsSchema.parse(raw);

  // Normalize: strip trailing slash from URL
  return { ...result, url: result.url.replace(/\/+$/, '') };
}
