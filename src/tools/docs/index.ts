import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import {
  getAllResources,
  getListedResources,
} from '../../resources/catalog.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const SNIPPET_LEN = 320;

/** Score a knowledge entry against the query terms (title weighted higher). */
function scoreEntry(
  content: string,
  uri: string,
  description: string,
  terms: string[],
): { score: number; snippet: string } {
  const hay = content.toLowerCase();
  const meta = `${uri} ${description}`.toLowerCase();
  let score = 0;
  let firstHit = -1;
  for (const t of terms) {
    if (meta.includes(t)) score += 3;
    let idx = hay.indexOf(t);
    while (idx !== -1) {
      score += 1;
      if (firstHit === -1 || idx < firstHit) firstHit = idx;
      idx = hay.indexOf(t, idx + t.length);
    }
  }
  let snippet = '';
  if (firstHit !== -1) {
    const start = Math.max(0, firstHit - 60);
    snippet = content
      .slice(start, start + SNIPPET_LEN)
      .replace(/\s+/g, ' ')
      .trim();
  } else {
    snippet = content.slice(0, SNIPPET_LEN).replace(/\s+/g, ' ').trim();
  }
  return { score, snippet };
}

export function registerDocsTools(
  server: McpServer,
  _client: StreamClient,
): void {
  registerTool(
    server,
    'search_docs',
    {
      description:
        'Search the embedded Stream knowledge base (architecture, auth, query ' +
        'languages SEQL/SCQL, CA management, lifecycle, templates, revocation, ' +
        'keystores, triggers, RBAC, TSA, SSH, system admin, tool selection, ' +
        'server rules) and return the best-matching topics with snippets. Use ' +
        'this to learn how to use the tools before acting; then read the full ' +
        'topic with get_doc.\nSafety tier: read-only',
      inputSchema: z.object({
        query: z
          .string()
          .min(1)
          .describe('Keywords, e.g. "create root CA" or "SCQL fields".'),
        max_results: z
          .number()
          .int()
          .positive()
          .max(10)
          .default(5)
          .describe('Maximum topics to return (default 5).'),
      }),
    },
    ({ query, max_results }) => {
      const terms = query
        .toLowerCase()
        .split(/\s+/)
        .map((t) => t.replace(/[^a-z0-9]/g, ''))
        .filter((t) => t.length > 1);
      // Only rank top-level (listed) topics; section URIs are reachable via get_doc.
      const ranked = getListedResources()
        .map((r) => {
          const { score, snippet } = scoreEntry(
            r.content,
            r.uri,
            r.description,
            terms,
          );
          return { uri: r.uri, title: r.description, score, snippet };
        })
        .filter((r) => r.score > 0)
        .sort((a, b) => b.score - a.score)
        .slice(0, max_results);
      return text(
        JSON.stringify({
          query,
          count: ranked.length,
          results: ranked.map(({ uri, title, snippet }) => ({
            uri,
            title,
            snippet,
          })),
          hint:
            ranked.length === 0
              ? 'No match. Try broader keywords, or list topics by reading stream://knowledge/tool-selection.'
              : 'Read a full topic with get_doc { uri }.',
        }),
      );
    },
  );

  registerTool(
    server,
    'get_doc',
    {
      description:
        'Return the full markdown of a Stream knowledge topic by its ' +
        'stream://knowledge/* URI (from search_docs results, or a known slug ' +
        'like stream://knowledge/ca-management). Section URIs ' +
        '(…/<topic>/<section>) are also accepted.\nSafety tier: read-only',
      inputSchema: z.object({
        uri: z
          .string()
          .describe(
            'A stream://knowledge/* URI. A bare slug (e.g. "ca-management") is ' +
              'also accepted and resolved under stream://knowledge/.',
          ),
      }),
    },
    ({ uri }) => {
      const normalized = uri.includes('://')
        ? uri
        : `stream://knowledge/${uri.replace(/^\/+/, '')}`;
      const entry = getAllResources().find((r) => r.uri === normalized);
      if (!entry) {
        const topics = getListedResources()
          .map((r) => r.uri)
          .join(', ');
        return text(
          JSON.stringify({
            error: `Unknown doc URI: ${normalized}`,
            available_topics: topics,
          }),
        );
      }
      return text(entry.content);
    },
  );
}
