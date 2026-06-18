import { afterAll, describe, expect, it } from 'vitest';

import { LocalAccountAuthProvider } from '../../src/auth/local.js';
import { StreamClient } from '../../src/client/http.js';

/**
 * Opt-in mutation smoke against live QA. The deterministic suites only exercise
 * mutating tools against mocks, so wire-shape drift (enum casing, PUT vs PATCH,
 * required fields) on a create/update/delete could ship undetected. This runs a
 * single idempotent create -> update -> delete cycle on a throwaway, side-effect-
 * free config object (a custom Extended Key Usage) and cleans up after itself.
 *
 * It writes to a SHARED QA instance, so it is gated behind an explicit opt-in:
 *   source .env.local && STREAM_E2E_MUTATE=1 bun run test:e2e
 */
const url = process.env.STREAM_E2E_URL;
const apiId = process.env.STREAM_E2E_API_ID;
const apiKey = process.env.STREAM_E2E_API_KEY;
const live = Boolean(url && apiId && apiKey);
const enabled = live && process.env.STREAM_E2E_MUTATE === '1';

// Unique throwaway identifiers so concurrent runs / leftovers do not collide.
const stamp = String(Date.now());
const NAME = `mcp-e2e-mutate-${stamp}`;
const OID = `1.3.6.1.4.1.59999.${stamp.slice(-7)}`;
const ROUTE = '/api/v1/extension/ekus';
const item = `${ROUTE}/${encodeURIComponent(OID)}`;

describe.skipIf(!enabled)(
  'mutation smoke (live QA, opt-in STREAM_E2E_MUTATE=1)',
  () => {
    const client = new StreamClient(
      url!,
      new LocalAccountAuthProvider(apiId!, apiKey!, 'local'),
      { timeout: 30, exportTimeout: 60, verifySsl: true },
    );

    afterAll(async () => {
      // Best-effort cleanup even if an assertion failed mid-cycle.
      try {
        await client.delete(item);
      } catch {
        /* already deleted */
      }
      await client.close();
    });

    it('round-trips create -> read -> update -> delete on a throwaway EKU', async () => {
      // create (custom:true is mandatory on the wire, like create_eku)
      await client.post(ROUTE, { name: NAME, oid: OID, custom: true });
      const created = await client.get<Record<string, unknown>>(item);
      expect(created.oid).toBe(OID);
      expect(created.name).toBe(NAME);

      // update (PUT on the collection root, keyed by oid; rename)
      const newName = `${NAME}-upd`;
      await client.put(ROUTE, { oid: OID, name: newName, custom: true });
      const updated = await client.get<Record<string, unknown>>(item);
      expect(updated.name).toBe(newName);

      // delete + confirm gone
      await client.delete(item);
      await expect(client.get(item)).rejects.toMatchObject({ statusCode: 404 });
    });
  },
);
