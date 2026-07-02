import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';

import { BUILD_TIMESTAMP_ISO } from '../build-info.js';
import {
  SECTION_URI_TEMPLATE,
  getAllResources,
  getListedResources,
  getResourceByUri,
} from './catalog.js';

function listKnowledgeTopics(): string[] {
  const prefix = 'stream://knowledge/';
  const topics = new Set<string>();
  for (const r of getAllResources()) {
    if (!r.uri.startsWith(prefix)) continue;
    const head = r.uri.slice(prefix.length).split('/')[0];
    if (head) topics.add(head);
  }
  return [...topics].sort();
}

function listSectionsFor(topic: string): string[] {
  const prefix = `stream://knowledge/${topic}/`;
  const sections = new Set<string>();
  for (const r of getAllResources()) {
    if (!r.uri.startsWith(prefix)) continue;
    const slug = r.uri.slice(prefix.length);
    if (slug && !slug.includes('/')) sections.add(slug);
  }
  return [...sections].sort();
}

// Resources are embedded markdown bundled at build time, so the build
// timestamp (BUILD_TIMESTAMP_ISO, injected by tsup; process start in dev) is a
// faithful "lastModified" for every entry.

export function registerAllResources(server: McpServer): void {
  for (const resource of getListedResources()) {
    server.registerResource(
      resource.name,
      resource.uri,
      {
        description: resource.description,
        mimeType: 'text/markdown',
        annotations: {
          audience: [...(resource.audience ?? ['assistant'])],
          priority: resource.priority ?? 0.5,
          lastModified: BUILD_TIMESTAMP_ISO,
        },
      },
      async (uri) => ({
        contents: [
          { uri: uri.href, mimeType: 'text/markdown', text: resource.content },
        ],
      }),
    );
  }

  // Unlisted resources (split sections): readable by URI, kept out of the list.
  for (const resource of getAllResources()) {
    if (resource.listed !== false) continue;
    server.registerResource(
      resource.name,
      resource.uri,
      {
        description: resource.description,
        mimeType: 'text/markdown',
        annotations: {
          audience: [...(resource.audience ?? ['assistant'])],
          priority: resource.priority ?? 0.3,
          lastModified: BUILD_TIMESTAMP_ISO,
        },
      },
      async (uri: URL) => ({
        contents: [
          { uri: uri.href, mimeType: 'text/markdown', text: resource.content },
        ],
      }),
    );
  }

  // Section URI template for clients that prefer templates over an enumerated list.
  server.registerResource(
    'knowledge-section-template',
    new ResourceTemplate(SECTION_URI_TEMPLATE, {
      list: undefined,
      complete: {
        topic: (value: string) =>
          listKnowledgeTopics().filter((t) => t.startsWith(value)),
        section: (value: string, ctx) => {
          const topic = (ctx?.arguments ?? {})['topic'];
          if (!topic) return [];
          return listSectionsFor(topic).filter((s) => s.startsWith(value));
        },
      },
    }),
    {
      description:
        'Section view of a knowledge topic (e.g. stream://knowledge/query-languages/scql-fields).',
      mimeType: 'text/markdown',
      annotations: { audience: ['assistant'], priority: 0.4 },
    },
    async (uri: URL) => {
      const entry = getResourceByUri(uri.href);
      if (!entry) throw new Error(`Section not found: ${uri.href}`);
      return {
        contents: [
          { uri: uri.href, mimeType: 'text/markdown', text: entry.content },
        ],
      };
    },
  );
}
