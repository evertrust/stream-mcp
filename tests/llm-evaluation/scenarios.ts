/**
 * Offline tool-selection scenarios for the deterministic ranker (no model, no
 * network). Each prompt must rank its expected tool in the top 5.
 */
export interface RankScenario {
  readonly question: string;
  readonly expectedTool: string;
}

export const RANK_SCENARIOS: readonly RankScenario[] = [
  {
    question:
      'Preview a CRL series for the offline root CA for the next ten years.',
    expectedTool: 'preview_crl_series',
  },
  {
    question: 'Generate and sign the previewed CRL series for the offline CA.',
    expectedTool: 'generate_crl_series',
  },
  {
    question: 'List the CRL series jobs and their status.',
    expectedTool: 'list_crl_series',
  },
  {
    question: 'Download the CRLs of the succeeded CRL series job as a zip.',
    expectedTool: 'download_crl_series',
  },
  {
    question: 'Delete the finished CRL series job.',
    expectedTool: 'delete_crl_series',
  },
];
