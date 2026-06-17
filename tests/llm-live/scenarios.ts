/**
 * Live LLM smoke scenarios. Kept SMALL and READ-ONLY: the runner executes a
 * full agent loop, so the model may actually call the first tool it picks —
 * mutating selections would write to the shared QA instance. Each scenario
 * costs a few model turns; ~8 per run is the design target.
 */
export interface LiveScenario {
  readonly id: string;
  readonly question: string;
  /** The model must call one of these (only read-only discovery may precede). */
  readonly acceptablePrimaryTools: readonly string[];
  /** Fail if any of these is called before an acceptable primary tool. */
  readonly forbiddenTools?: readonly string[];
  /** The chosen primary tool's input must include all of these keys. */
  readonly requiredArgs?: readonly string[];
  /**
   * Case-insensitive substrings the FINAL assistant answer must contain. This
   * is the "usable output" check: it proves the model surfaced real tool output
   * into its answer, not just that it picked a tool.
   */
  readonly expectInAnswer?: readonly string[];
  readonly maxBudgetUsd?: number;
}

export const LIVE_SCENARIOS: readonly LiveScenario[] = [
  {
    id: 'whoami',
    question: 'Who am I in Stream and what roles and permissions do I have?',
    acceptablePrimaryTools: ['whoami'],
    // Usable-output proof: the answer must name the authenticated account.
    expectInAnswer: ['sbo-claude-mcp'],
  },
  {
    id: 'list-cas',
    question: 'List the X.509 certificate authorities configured in Stream.',
    acceptablePrimaryTools: ['list_cas'],
  },
  {
    id: 'search-certificates',
    question: 'Search Stream for some issued certificates and show me a few.',
    acceptablePrimaryTools: ['search_certificates', 'aggregate_certificates'],
    requiredArgs: ['query'],
  },
  {
    id: 'list-templates',
    question: 'What X.509 certificate templates are available in Stream?',
    acceptablePrimaryTools: ['list_templates', 'list_requestable_templates'],
  },
  {
    id: 'list-keystores',
    question: 'List the cryptographic keystores configured in Stream.',
    acceptablePrimaryTools: ['list_keystores'],
  },
  {
    id: 'license-info',
    question: 'What Stream version is running and which modules are licensed?',
    acceptablePrimaryTools: ['get_license_info', 'get_license_modules'],
  },
  {
    id: 'ca-from-scratch-docs',
    question:
      'How do I create a managed root CA from scratch in Stream? Explain the steps.',
    // Reading docs / inspecting the create schema are both correct grounding moves.
    acceptablePrimaryTools: ['search_docs', 'get_doc', 'describe_ca_schema'],
    maxBudgetUsd: 0.9,
  },
  {
    id: 'audit-events',
    question: 'Search the Stream audit log for recent events.',
    acceptablePrimaryTools: ['search_events'],
    requiredArgs: ['query'],
  },
] as const;
