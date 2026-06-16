/**
 * Embedded knowledge-resource catalog (stream://knowledge/*).
 *
 * Knowledge markdown files live under src/resources/knowledge/ and are inlined
 * at build time by tsup's `.md -> text` loader. The catalog arrays start empty;
 * the knowledge-authoring phase imports the .md files and appends entries here.
 */
export type ResourceAudience = 'user' | 'assistant';

export interface ResourceEntry {
  readonly name: string;
  readonly uri: string;
  readonly description: string;
  readonly content: string;
  readonly splitSections?: boolean;
  /** Priority 0..1 - clients use this to rank context inclusion. */
  readonly priority?: number;
  /** Intended audience(s); defaults to ["assistant"]. */
  readonly audience?: readonly ResourceAudience[];
  /** When false, omit from the default `resources/list` to keep it short. */
  readonly listed?: boolean;
}

// Populated during the knowledge-authoring phase.
const CORE_RESOURCES: readonly ResourceEntry[] = [];
const CURATED_RESOURCES: readonly ResourceEntry[] = [];

function slugifyHeading(title: string): string {
  return title
    .toLowerCase()
    .replace(/[`"'’]/g, '')
    .replace(/&/g, ' and ')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

type SectionCandidate = { readonly title: string; readonly body: string };

function splitMarkdownSections(content: string): SectionCandidate[] {
  const lines = content.split('\n');
  const sections: string[] = [];
  let current: string[] = [];

  for (const line of lines) {
    if (line.startsWith('## ')) {
      if (current.length > 0) sections.push(current.join('\n'));
      current = [line];
      continue;
    }
    if (current.length > 0) current.push(line);
  }
  if (current.length > 0) sections.push(current.join('\n'));

  return sections
    .map((section) => {
      const [first, ...rest] = section.trim().split('\n');
      const title = first?.replace(/^## /, '').trim() ?? '';
      if (!title) return undefined;
      return { title, body: rest.join('\n').trim() } satisfies SectionCandidate;
    })
    .filter((entry): entry is SectionCandidate => entry !== undefined);
}

function createSectionContent(
  resource: ResourceEntry,
  section: SectionCandidate,
): string {
  return [
    `# ${section.title}`,
    '',
    `Parent resource: ${resource.uri}`,
    `Parent topic: ${resource.description}`,
    '',
    section.body,
  ].join('\n');
}

function splitSections(resource: ResourceEntry): ResourceEntry[] {
  if (!resource.splitSections) return [];
  return splitMarkdownSections(resource.content)
    .map((section) => {
      const slug = slugifyHeading(section.title);
      if (!section.title || !slug) return undefined;
      const entry: ResourceEntry = {
        name: `${resource.name}-${slug}`,
        uri: `${resource.uri}/${slug}`,
        description: `${resource.description} - ${section.title}`,
        content: createSectionContent(resource, section),
        listed: false,
        priority: 0.3,
      };
      return entry;
    })
    .filter((entry): entry is ResourceEntry => entry !== undefined);
}

const SECTION_RESOURCES = CORE_RESOURCES.flatMap(splitSections);

/** Every known resource, including unlisted section URIs. */
export function getAllResources(): ResourceEntry[] {
  return [...CORE_RESOURCES, ...CURATED_RESOURCES, ...SECTION_RESOURCES];
}

/** Resources to advertise in `resources/list`. Skips unlisted entries. */
export function getListedResources(): ResourceEntry[] {
  return getAllResources().filter((r) => r.listed !== false);
}

/** Resolve a single resource by URI (listed or unlisted). */
export function getResourceByUri(uri: string): ResourceEntry | undefined {
  return getAllResources().find((r) => r.uri === uri);
}

/** URI template that covers split-section resources. */
export const SECTION_URI_TEMPLATE = 'stream://knowledge/{topic}/{section}';
