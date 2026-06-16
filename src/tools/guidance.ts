/**
 * Per-tool disambiguation hints surfaced to the model alongside the tool
 * description. Compact format:
 *
 *   [when: <fragment> | not: <fragment> | pre: <fragment>]
 *
 * Only tools whose role could be confused with a sibling need an entry.
 * Entries are added as domains land; the map starts small.
 */
export interface ToolGuidance {
  readonly useWhen: string;
  readonly doNotUseWhen: string;
  readonly beforeCall?: string;
}

const EXPLICIT_GUIDANCE: Record<string, ToolGuidance> = {};

function getGuidance(name: string): ToolGuidance | undefined {
  return EXPLICIT_GUIDANCE[name];
}

export function buildToolDescription(
  name: string,
  description?: string,
): string | undefined {
  if (!description) return description;
  // Honor a pre-stamped compact form.
  if (description.includes('[when:') && description.includes(' | not:')) {
    return description;
  }
  const guidance = getGuidance(name);
  if (!guidance) return description;

  let suffix = `\n[when: ${guidance.useWhen} | not: ${guidance.doNotUseWhen}`;
  if (guidance.beforeCall) suffix += ` | pre: ${guidance.beforeCall}`;
  suffix += ']';
  return `${description.trimEnd()}${suffix}`;
}
