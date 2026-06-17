/**
 * Live, model-driven smoke suite. Drives a small Claude model (default Sonnet,
 * override with STREAM_LLM_LIVE_MODEL) against the local Stream MCP and asserts
 * the model both SELECTS the right tool and surfaces a USABLE answer from it.
 *
 * COSTS MONEY — opt-in. Run with:
 *   source .env.local && STREAM_LLM_LIVE=1 bun run test:llm:live
 *
 * Skipped automatically (no model call, no billing) when ANY of:
 *   - STREAM_LLM_LIVE is not "1" (the mandatory paid opt-in)
 *   - the `claude` binary is not on PATH
 *   - ANTHROPIC_API_KEY is set (refuses an explicit API key)
 *   - STREAM_E2E_* env vars are missing (the config does NOT auto-load .env.local)
 */
import { describe, expect, it } from 'vitest';

import { liveSuiteEnabled, liveSuiteSkipReason } from './auth.js';
import { DEFAULT_LIVE_MODEL, runScenarioWithClaude } from './runner.js';
import { LIVE_SCENARIOS } from './scenarios.js';

const HAS_E2E_CREDS =
  Boolean(process.env['STREAM_E2E_URL']) &&
  Boolean(process.env['STREAM_E2E_API_ID']) &&
  Boolean(process.env['STREAM_E2E_API_KEY']);

// Explicit, mandatory opt-in: this suite costs money, so it never runs unless
// STREAM_LLM_LIVE=1 is set IN ADDITION to having creds + an authenticated CLI.
const OPTED_IN = process.env['STREAM_LLM_LIVE'] === '1';

const SKIP = !OPTED_IN || !liveSuiteEnabled() || !HAS_E2E_CREDS;
const SKIP_REASON = !OPTED_IN
  ? 'opt-in required: set STREAM_LLM_LIVE=1 (this suite calls a real model and costs money)'
  : !liveSuiteEnabled()
    ? liveSuiteSkipReason()
    : 'STREAM_E2E_* env vars are not set (source .env.local first)';

const isDiscovery = (n: string): boolean =>
  /^(list_|get_|search_|describe_|aggregate_)/.test(n) || n === 'whoami';

describe.skipIf(SKIP)(`Live LLM smoke (model = ${DEFAULT_LIVE_MODEL})`, () => {
  if (SKIP) {
    it(`is skipped: ${SKIP_REASON}`, () => expect(true).toBe(true));
    return;
  }

  it.each(LIVE_SCENARIOS.map((s) => ({ ...s, toString: () => s.id })))(
    'model selects the right tool and produces usable output for %s',
    async (scenario) => {
      const result = await runScenarioWithClaude(scenario.question, {
        maxBudgetUsd: scenario.maxBudgetUsd,
      });

      expect(
        result.errors,
        `SDK reported errors: ${result.errors.join(', ')}`,
      ).toEqual([]);

      expect(
        result.toolCalls.length,
        `Model called no Stream tool. Full sequence: ` +
          `${result.allToolCalls.join(' -> ') || 'none'}. ` +
          `Said: ${result.assistantText.slice(0, 300)}`,
      ).toBeGreaterThan(0);

      // An acceptable primary tool must be reached; only read-only discovery
      // tools may precede it (no flailing into unrelated/mutating actions).
      const primaryIndex = result.toolCalls.findIndex((n) =>
        scenario.acceptablePrimaryTools.includes(n),
      );
      expect(
        primaryIndex,
        `None of ${JSON.stringify(scenario.acceptablePrimaryTools)} called. ` +
          `Sequence: ${result.allToolCalls.join(' -> ')}`,
      ).toBeGreaterThanOrEqual(0);

      const precedingNonDiscovery = result.toolCalls
        .slice(0, primaryIndex)
        .filter((n) => !isDiscovery(n));
      expect(
        precedingNonDiscovery,
        `Non-discovery tool(s) called before the primary: ${precedingNonDiscovery.join(', ')}`,
      ).toEqual([]);

      const primaryTool = result.toolCalls[primaryIndex]!;
      for (const forbidden of scenario.forbiddenTools ?? []) {
        const fi = result.toolCalls.indexOf(forbidden);
        if (fi !== -1 && fi < primaryIndex) {
          expect.fail(`Forbidden tool '${forbidden}' called before primary.`);
        }
      }

      for (const arg of scenario.requiredArgs ?? []) {
        const args = result.toolInputs.get(primaryTool) ?? {};
        expect(
          Object.prototype.hasOwnProperty.call(args, arg),
          `Primary '${primaryTool}' missing arg '${arg}'. Args: ${JSON.stringify(args)}`,
        ).toBe(true);
      }

      // Usable-output check: the final answer reflects real tool output.
      const answer = result.assistantText.toLowerCase();
      for (const needle of scenario.expectInAnswer ?? []) {
        expect(
          answer,
          `Answer did not contain "${needle}". Answer: ${result.assistantText.slice(0, 400)}`,
        ).toContain(needle.toLowerCase());
      }

      console.log(
        `[${scenario.id}] cost=$${result.totalCostUsd.toFixed(4)} ` +
          `turns=${result.turns} mcp=[${result.toolCalls.join(', ')}]`,
      );
    },
    180_000,
  );
});
