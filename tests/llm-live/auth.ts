/**
 * Gate for the paid, model-driven LLM smoke suite. It drives the Claude Agent
 * SDK, which spawns the bundled `claude` binary headlessly and inherits its
 * auth.
 *
 * BILLING WARNING: headless `claude -p` / Agent SDK runs are metered as
 * Anthropic API usage — even with a Pro/Max/Team subscription session. This
 * suite COSTS money. It is opt-in: run it deliberately, never in CI or by
 * default. The gate refuses to run when an explicit ANTHROPIC_API_KEY is set
 * (a guard against the most surprising billing case, not a zero-cost promise).
 */
import { spawnSync } from 'node:child_process';

interface SdkAuthInfo {
  readonly status: 'ok' | 'missing-binary' | 'no-subscription';
  readonly reason?: string;
}

export function probeSdkAuth(): SdkAuthInfo {
  const which = spawnSync('which', ['claude'], { encoding: 'utf-8' });
  if (which.status !== 0 || !which.stdout.trim()) {
    return {
      status: 'missing-binary',
      reason: '`claude` binary not found on PATH - install Claude Code first.',
    };
  }
  if (process.env['ANTHROPIC_API_KEY']) {
    return {
      status: 'no-subscription',
      reason:
        'ANTHROPIC_API_KEY is set; the live suite refuses to run with an ' +
        'explicit API key. (Headless runs are billed as API usage regardless.)',
    };
  }
  return { status: 'ok' };
}

export function liveSuiteEnabled(): boolean {
  return probeSdkAuth().status === 'ok';
}

export function liveSuiteSkipReason(): string {
  return probeSdkAuth().reason ?? 'live suite enabled';
}
