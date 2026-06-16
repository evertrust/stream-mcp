/**
 * Embedded knowledge-resource catalog (stream://knowledge/*).
 *
 * Knowledge markdown files live under src/resources/knowledge/ and are inlined
 * at build time by tsup's `.md -> text` loader.
 */
import architectureContent from './knowledge/architecture.md';
import authenticationContent from './knowledge/authentication.md';
import caManagementContent from './knowledge/ca-management.md';
import keystoresContent from './knowledge/keystores.md';
import lifecycleContent from './knowledge/lifecycle.md';
import queryLanguagesContent from './knowledge/query-languages.md';
import rbacContent from './knowledge/rbac.md';
import revocationContent from './knowledge/revocation.md';
import serverRulesContent from './knowledge/server_rules.md';
import sshContent from './knowledge/ssh.md';
import systemAdminContent from './knowledge/system_admin.md';
import templatesContent from './knowledge/templates.md';
import toolSelectionContent from './knowledge/tool_selection.md';
import triggersContent from './knowledge/triggers.md';
import tsaContent from './knowledge/tsa.md';

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

const CORE_RESOURCES: readonly ResourceEntry[] = [
  {
    name: 'server-rules',
    uri: 'stream://knowledge/server-rules',
    description: 'Operating rules and conventions for the Stream MCP server',
    content: serverRulesContent,
    priority: 0.95,
  },
  {
    name: 'tool-selection',
    uri: 'stream://knowledge/tool-selection',
    description: 'Deterministic intent-to-tool selection playbook',
    content: toolSelectionContent,
    priority: 1.0,
  },
  {
    name: 'query-languages',
    uri: 'stream://knowledge/query-languages',
    description: 'SCQL (certificates) and SEQL (events) query syntax',
    content: queryLanguagesContent,
    splitSections: true,
    priority: 0.95,
  },
  {
    name: 'architecture',
    uri: 'stream://knowledge/architecture',
    description: 'Stream 2.1 modules and object model overview',
    content: architectureContent,
    priority: 0.8,
  },
  {
    name: 'authentication',
    uri: 'stream://knowledge/authentication',
    description: 'Local-account and X509/mTLS authentication',
    content: authenticationContent,
  },
  {
    name: 'ca-management',
    uri: 'stream://knowledge/ca-management',
    description: 'X509 CA lifecycle: create from scratch vs import, issue, CRL',
    content: caManagementContent,
    splitSections: true,
    priority: 0.85,
  },
  {
    name: 'lifecycle',
    uri: 'stream://knowledge/lifecycle',
    description: 'Certificate enrollment and revocation (X509 + SSH)',
    content: lifecycleContent,
  },
  {
    name: 'templates',
    uri: 'stream://knowledge/templates',
    description: 'X509 profiles and SSH certificate templates',
    content: templatesContent,
  },
  {
    name: 'revocation',
    uri: 'stream://knowledge/revocation',
    description: 'CRL info, OCSP signers, and external revocation-list storage',
    content: revocationContent,
  },
  {
    name: 'keystores',
    uri: 'stream://knowledge/keystores',
    description: 'Keystores, private keys, and HSM introspection',
    content: keystoresContent,
  },
  {
    name: 'triggers',
    uri: 'stream://knowledge/triggers',
    description: 'Email/REST/expiration notification triggers',
    content: triggersContent,
  },
  {
    name: 'rbac',
    uri: 'stream://knowledge/rbac',
    description: 'Roles, local identities, identity providers, credentials',
    content: rbacContent,
  },
  {
    name: 'tsa',
    uri: 'stream://knowledge/tsa',
    description: 'Timestamping authorities, signers, and NTP clients',
    content: tsaContent,
  },
  {
    name: 'ssh',
    uri: 'stream://knowledge/ssh',
    description: 'OpenSSH CAs, templates, certificates, lifecycle, KRLs',
    content: sshContent,
  },
  {
    name: 'system-admin',
    uri: 'stream://knowledge/system-admin',
    description: 'System config, proxies, queues, license, dictionaries, audit',
    content: systemAdminContent,
  },
] as const;

const CURATED_RESOURCES: readonly ResourceEntry[] = [] as const;

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
