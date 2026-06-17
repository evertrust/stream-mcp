import { relative, resolve } from 'node:path';

import {
  collectMcpPathReferences,
  collectStreamOperations,
  resolveTruthInputs,
  verifyMcpRouteTruth,
  writeTruthArtifacts,
} from './lib/truth.js';

function formatReferenceIssue(issue: {
  path: string;
  details: string;
  file?: string;
  line?: number;
  method?: string;
}): string {
  const location =
    issue.file && issue.line ? ` (${issue.file}:${issue.line})` : '';
  const method = issue.method ? `${issue.method} ` : '';
  return `- ${method}${issue.path}${location}: ${issue.details}`;
}

function hasFlag(flag: string): boolean {
  return process.argv.slice(2).includes(flag);
}

async function main(): Promise<void> {
  const projectRoot = resolve(import.meta.dirname, '..');
  const inputs = resolveTruthInputs(projectRoot);
  const writeArtifacts = hasFlag('--write');

  const streamOperations = collectStreamOperations(
    inputs.streamRoot,
    projectRoot,
  );
  const references = collectMcpPathReferences(projectRoot);
  const verification = verifyMcpRouteTruth({
    streamOperations,
    references,
  });

  if (writeArtifacts) {
    writeTruthArtifacts({
      outputDir: inputs.outputDir,
      streamRoot: relative(projectRoot, inputs.streamRoot),
      references,
      streamOperations,
    });
  }

  console.log(
    `Truth input: stream=${relative(projectRoot, inputs.streamRoot)} (${streamOperations.length} routes)`,
  );
  console.log(
    `Verified MCP API references: ${verification.verifiedCount}/${verification.referencedCount}`,
  );
  console.log(
    `Allowlisted (unverifiable) references: ${verification.allowlistedCount}`,
  );
  console.log(`Issues: ${verification.issues.length}`);

  if (verification.issues.length > 0) {
    console.error('\nRoute truth verification failed:\n');
    for (const issue of verification.issues) {
      console.error(formatReferenceIssue(issue));
    }
    process.exitCode = 1;
    return;
  }

  console.log('Route truth verification passed.');
}

await main();
