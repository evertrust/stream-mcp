import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';

const HTTP_METHOD_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/;
// Play sub-router include, e.g. `-> /api/v1/ssh api.ssh.Routes` (root) or the
// relative `-> /cas api.ssh.ca.Routes` (nested inside api.ssh.routes). Stream
// mounts SSH only through nested includes, so the parser must recurse.
const INCLUDE_RE = /^\s*->\s+(\S+)\s+([A-Za-z0-9._]+)\.Routes\b/;
// Allows `(`, `)`, `,` so template literals like
// `/api/v1/.../${encodePathSegment(id)}` are captured as a single fragment.
// Whitespace stays excluded so the match still terminates at the end of the
// string concatenation.
const PATH_FRAGMENT_RE = /\/api\/v1\/[A-Za-z0-9_./${}<>(),\-:*]+/g;
// StreamClient verbs, mapped to HTTP methods below.
const CLIENT_METHOD_NAMES = new Set([
  'get',
  'getList',
  'getText',
  'getBytes',
  'post',
  'postMultipart',
  'put',
  'patch',
  'delete',
]);

// MCP /api/v1 references that legitimately have no matching line in the Stream
// backend's `conf` routes (e.g. paths assembled dynamically that the static
// parser cannot reconstruct). Keep this empty unless a real gap is confirmed.
export const ALLOWED_UNVERIFIED_PATHS = new Set<string>([
  // Path-prefix constant only: `HSMS_ROUTE` is used solely to build
  // `/api/v1/crypto/hsms/{library}` and `.../{library}/slots` (both real
  // routes). HSMs have no bare collection endpoint in the backend.
  '/api/v1/crypto/hsms',
]);

// /api/v1 routes deliberately NOT exposed as tools (used by the advisory
// reverse-coverage report so genuine gaps stand out from intentional omissions).
export const INTENTIONALLY_UNWRAPPED_PATHS = new Set<string>([
  // Session login/logout: programmatic clients authenticate per-request via
  // headers / mTLS, so there is no interactive login step to wrap.
  '/api/v1/security/principals/authenticate',
  '/api/v1/security/principals/logout',
]);

export interface NormalizedOperation {
  method: string;
  path: string;
  sourceFile: string;
}

export interface McpPathReference {
  path: string;
  file: string;
  line: number;
  rawPath: string;
  method?: string;
}

export interface RouteTruthIssue {
  type: 'allowlist_stale' | 'method_mismatch' | 'missing_route';
  path: string;
  file?: string;
  line?: number;
  method?: string;
  details: string;
}

export interface RouteTruthVerification {
  issues: RouteTruthIssue[];
  verifiedCount: number;
  allowlistedCount: number;
  referencedCount: number;
}

export interface TruthInputs {
  projectRoot: string;
  streamRoot: string;
  outputDir: string;
}

interface StoredOperationsDocument {
  routes?: unknown;
}

function expandHome(pathValue: string): string {
  if (!pathValue.startsWith('~/')) {
    return pathValue;
  }
  return join(homedir(), pathValue.slice(2));
}

function resolveExistingPath(
  projectRoot: string,
  candidates: readonly string[],
): string {
  for (const candidate of candidates) {
    const resolved = candidate.startsWith('/')
      ? candidate
      : resolve(projectRoot, candidate);
    if (existsSync(expandHome(resolved))) {
      return expandHome(resolved);
    }
  }
  throw new Error(
    `Could not resolve any of the required paths: ${candidates.join(', ')}`,
  );
}

export function resolveTruthInputs(projectRoot: string): TruthInputs {
  // Prefer the live Stream backend checkout; fall back to the committed
  // routes snapshot so CI can verify offline without the backend repo.
  const streamRoot = resolveExistingPath(
    projectRoot,
    [
      process.env['STREAM_SOURCE_ROOT'] ?? '',
      '../stream',
      'src/generated/docs/stream-routes.json',
      '/Users/sbo/Documents/EVERTRUST/stream',
    ].filter(Boolean),
  );
  const outputDir = resolve(
    projectRoot,
    process.env['STREAM_TRUTH_OUTPUT_DIR'] ?? 'src/generated/docs',
  );
  return { projectRoot, streamRoot, outputDir };
}

function collectFiles(root: string, extension: string): string[] {
  const files: string[] = [];

  function walk(dir: string): void {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith(extension)) {
        files.push(fullPath);
      }
    }
  }

  walk(root);
  return files.sort();
}

function readText(path: string): string {
  return readFileSync(path, 'utf8');
}

function isNormalizedOperation(value: unknown): value is NormalizedOperation {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    typeof (value as NormalizedOperation).method === 'string' &&
    typeof (value as NormalizedOperation).path === 'string' &&
    typeof (value as NormalizedOperation).sourceFile === 'string'
  );
}

function sortOperations(
  operations: readonly NormalizedOperation[],
): NormalizedOperation[] {
  return [...operations].sort((left, right) => {
    const pathOrder = left.path.localeCompare(right.path);
    if (pathOrder !== 0) {
      return pathOrder;
    }
    const methodOrder = left.method.localeCompare(right.method);
    if (methodOrder !== 0) {
      return methodOrder;
    }
    return left.sourceFile.localeCompare(right.sourceFile);
  });
}

function readStoredOperations(
  inputPath: string,
): NormalizedOperation[] | undefined {
  if (!inputPath.endsWith('.json')) {
    return undefined;
  }

  const document = JSON.parse(readText(inputPath)) as StoredOperationsDocument;
  const operations = document.routes;
  if (!Array.isArray(operations)) {
    return undefined;
  }

  return sortOperations(
    operations.filter(isNormalizedOperation).map((operation) => ({
      method: operation.method,
      path: normalizeRoutePath(operation.path),
      sourceFile: operation.sourceFile,
    })),
  );
}

function lineNumberAt(
  sourceFile: ts.SourceFile,
  nodeOrIndex: ts.Node | number,
): number {
  const position =
    typeof nodeOrIndex === 'number'
      ? nodeOrIndex
      : nodeOrIndex.getStart(sourceFile);
  return sourceFile.getLineAndCharacterOfPosition(position).line + 1;
}

function expressionTemplateText(
  sourceFile: ts.SourceFile,
  expression: ts.Expression,
): string {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  return expression.getText(sourceFile).trim();
}

function extractLiteralText(
  sourceFile: ts.SourceFile,
  expression: ts.Expression,
): string | undefined {
  if (ts.isStringLiteralLike(expression)) {
    return expression.text;
  }

  if (!ts.isTemplateExpression(expression)) {
    return undefined;
  }

  let value = expression.head.text;
  for (const span of expression.templateSpans) {
    value += `\${${expressionTemplateText(sourceFile, span.expression)}}`;
    value += span.literal.text;
  }

  return value;
}

export function normalizeRoutePath(rawPath: string): string {
  let normalized = rawPath.trim();
  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }

  normalized = normalized
    .replace(/\$\{[^}]+\}/g, '{param}')
    .replace(/\$([A-Za-z0-9_]+)<[^>]+>/g, '{$1}')
    .replace(/:([A-Za-z0-9_]+)/g, '{$1}')
    .replace(/\*([A-Za-z0-9_]+)/g, '{$1}')
    .replace(/\/+/g, '/');

  if (normalized.length > 1 && normalized.endsWith('/')) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

function canonicalRoutePath(rawPath: string): string {
  return normalizeRoutePath(rawPath).replace(/\{[^}]+\}/g, '{}');
}

function extractApiPathFragments(rawText: string): string[] {
  return [...rawText.matchAll(PATH_FRAGMENT_RE)]
    .map((match) => match[0])
    .filter((value): value is string => Boolean(value))
    .map((value) => value.replace(/[),.;:]+$/g, ''));
}

function resolveKnownConstants(
  rawValue: string,
  constPathMap: ReadonlyMap<string, string>,
): string {
  let resolved = rawValue;
  let mutated = true;

  while (mutated) {
    mutated = false;
    resolved = resolved.replace(/\$\{([A-Za-z0-9_]+)\}/g, (full, name) => {
      const replacement = constPathMap.get(name);
      if (!replacement) {
        return full;
      }
      mutated = true;
      return replacement;
    });
  }

  return resolved;
}

function joinRoutePath(basePath: string, subPath: string): string {
  if (subPath === '/' || subPath === '') {
    return normalizeRoutePath(basePath);
  }
  const joined = `${basePath.replace(/\/+$/, '')}/${subPath.replace(/^\/+/, '')}`;
  return normalizeRoutePath(joined);
}

function routeFileForModule(streamRoot: string, moduleName: string): string {
  return join(streamRoot, 'conf', `${moduleName}.routes`);
}

// Recursively walk a Play routes file, following `->` sub-router includes
// (resolved relative to the current base path) and recording method lines.
// `visited` is keyed by file so a module mounted under several bases is parsed
// once (the first/top-level mount wins) and cycles are impossible.
function collectFromRouteFile(
  streamRoot: string,
  routeFile: string,
  basePath: string,
  projectRoot: string,
  operations: NormalizedOperation[],
  visited: Set<string>,
): void {
  if (visited.has(routeFile)) {
    return;
  }
  visited.add(routeFile);

  for (const line of readText(routeFile).split('\n')) {
    const includeMatch = line.match(INCLUDE_RE);
    if (includeMatch) {
      const [, subPath, moduleName] = includeMatch;
      if (!subPath || !moduleName) {
        continue;
      }
      const moduleFile = routeFileForModule(streamRoot, moduleName);
      if (!existsSync(moduleFile)) {
        continue;
      }
      collectFromRouteFile(
        streamRoot,
        moduleFile,
        joinRoutePath(basePath, subPath),
        projectRoot,
        operations,
        visited,
      );
      continue;
    }

    const methodMatch = line.match(HTTP_METHOD_RE);
    if (!methodMatch) {
      continue;
    }
    const parts = line.trim().split(/\s+/);
    const method = methodMatch[1]!;
    const subPath = parts[1];
    if (!subPath) {
      continue;
    }

    operations.push({
      method,
      path: joinRoutePath(basePath, subPath),
      sourceFile: relative(projectRoot, routeFile),
    });
  }
}

export function collectStreamOperations(
  streamRoot: string,
  projectRoot = process.cwd(),
): NormalizedOperation[] {
  const storedOperations = readStoredOperations(streamRoot);
  if (storedOperations) {
    return storedOperations;
  }

  const operations: NormalizedOperation[] = [];
  collectFromRouteFile(
    streamRoot,
    join(streamRoot, 'conf', 'routes'),
    '',
    projectRoot,
    operations,
    new Set<string>(),
  );

  return sortOperations(operations);
}

function clientMethodToHttp(methodName: string): string {
  if (
    methodName === 'get' ||
    methodName === 'getList' ||
    methodName === 'getText' ||
    methodName === 'getBytes'
  ) {
    return 'GET';
  }
  if (methodName === 'post' || methodName === 'postMultipart') {
    return 'POST';
  }
  return methodName.toUpperCase();
}

export function collectMcpPathReferences(
  projectRoot: string,
): McpPathReference[] {
  const srcRoot = join(projectRoot, 'src');
  const references: McpPathReference[] = [];

  for (const file of collectFiles(srcRoot, '.ts')) {
    if (file.includes(`${join('src', 'generated', 'docs')}`)) {
      continue;
    }

    const text = readText(file);
    const sourceFile = ts.createSourceFile(
      file,
      text,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );
    const rawConstMap = new Map<string, string>();
    const constPathMap = new Map<string, string>();

    function collectConstants(node: ts.Node): void {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer
      ) {
        const literal = extractLiteralText(sourceFile, node.initializer);
        if (literal) {
          rawConstMap.set(node.name.text, literal);
        }
      }
      ts.forEachChild(node, collectConstants);
    }

    collectConstants(sourceFile);

    let resolvedAny = true;
    while (resolvedAny) {
      resolvedAny = false;
      for (const [constName, literal] of rawConstMap) {
        const resolved = resolveKnownConstants(literal, constPathMap);
        const pathFragments = extractApiPathFragments(resolved);
        if (
          pathFragments.length === 1 &&
          constPathMap.get(constName) !== pathFragments[0]
        ) {
          constPathMap.set(constName, pathFragments[0]!);
          resolvedAny = true;
        }
      }
    }

    function recordReference(
      rawValue: string,
      node: ts.Node,
      method?: string,
    ): void {
      const resolved = resolveKnownConstants(rawValue, constPathMap);
      const pathFragments = extractApiPathFragments(resolved);
      if (pathFragments.length === 0) {
        return;
      }

      for (const rawPath of pathFragments) {
        references.push({
          path: normalizeRoutePath(rawPath),
          file: relative(projectRoot, file),
          line: lineNumberAt(sourceFile, node),
          rawPath,
          method,
        });
      }
    }

    function visit(node: ts.Node): void {
      // `const ROUTE = '/api/v1/...'`
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer
      ) {
        const literal = extractLiteralText(sourceFile, node.initializer);
        if (literal) {
          recordReference(literal, node);
        }
      }

      // ConfigSpec object properties: `routeCollection: '/api/v1/...'`,
      // `routeItem: '/api/v1/.../{name}'`, `collection`, `item`, etc.
      // Guarded to literal route values (not prose that happens to mention a
      // path) by requiring the value to start with the API prefix or a
      // `${const}` placeholder that resolves to one.
      if (ts.isPropertyAssignment(node) && node.initializer) {
        const literal = extractLiteralText(sourceFile, node.initializer);
        if (
          literal &&
          (literal.trimStart().startsWith('/api/v1') || literal.includes('${'))
        ) {
          recordReference(literal, node);
        }
      }

      // `client.get('/api/v1/...')` and friends.
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.getText(sourceFile) === 'client' &&
        CLIENT_METHOD_NAMES.has(node.expression.name.text)
      ) {
        const firstArgument = node.arguments[0];
        let rawValue: string | undefined;

        if (firstArgument) {
          rawValue = extractLiteralText(sourceFile, firstArgument);
          if (!rawValue && ts.isIdentifier(firstArgument)) {
            rawValue = rawConstMap.get(firstArgument.text);
          }
        }

        if (rawValue) {
          recordReference(
            rawValue,
            node,
            clientMethodToHttp(node.expression.name.text),
          );
        }
      }

      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
  }

  return references.sort((left, right) => {
    const pathOrder = left.path.localeCompare(right.path);
    if (pathOrder !== 0) {
      return pathOrder;
    }
    const fileOrder = left.file.localeCompare(right.file);
    if (fileOrder !== 0) {
      return fileOrder;
    }
    return left.line - right.line;
  });
}

function addMethod(
  map: Map<string, Set<string>>,
  path: string,
  method: string,
): void {
  const methods = map.get(path) ?? new Set<string>();
  methods.add(method);
  map.set(path, methods);
}

function methodMap(
  operations: readonly NormalizedOperation[],
): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();
  for (const operation of operations) {
    addMethod(map, canonicalRoutePath(operation.path), operation.method);
  }
  return map;
}

export function verifyMcpRouteTruth(params: {
  streamOperations: readonly NormalizedOperation[];
  references: readonly McpPathReference[];
  allowlist?: ReadonlySet<string>;
}): RouteTruthVerification {
  const sourceMap = methodMap(params.streamOperations);
  const allowlist = new Set(
    [...(params.allowlist ?? ALLOWED_UNVERIFIED_PATHS)].map((path) =>
      canonicalRoutePath(path),
    ),
  );
  const issues: RouteTruthIssue[] = [];

  for (const allowedPath of allowlist) {
    if (sourceMap.has(allowedPath)) {
      issues.push({
        type: 'allowlist_stale',
        path: allowedPath,
        details:
          'This allowlist entry is now present in the Stream routes and should be removed from ALLOWED_UNVERIFIED_PATHS.',
      });
    }
  }

  let verifiedCount = 0;
  let allowlistedCount = 0;

  for (const reference of params.references) {
    const referencePath = canonicalRoutePath(reference.path);
    const sourceMethods = sourceMap.get(referencePath);

    if (sourceMethods) {
      if (
        reference.method &&
        sourceMethods.size > 0 &&
        !sourceMethods.has(reference.method)
      ) {
        issues.push({
          type: 'method_mismatch',
          path: reference.path,
          file: reference.file,
          line: reference.line,
          method: reference.method,
          details: `Referenced as ${reference.method}, but the Stream route only exposes ${[...sourceMethods].sort().join(', ')}.`,
        });
        continue;
      }

      verifiedCount += 1;
      continue;
    }

    if (allowlist.has(referencePath)) {
      allowlistedCount += 1;
      continue;
    }

    issues.push({
      type: 'missing_route',
      path: reference.path,
      file: reference.file,
      line: reference.line,
      method: reference.method,
      details:
        'The route is not present in the Stream backend routes (../stream/conf). If this path is assembled dynamically and is genuinely valid, add it to ALLOWED_UNVERIFIED_PATHS.',
    });
  }

  return {
    issues,
    verifiedCount,
    allowlistedCount,
    referencedCount: params.references.length,
  };
}

/**
 * Reverse-direction coverage: which Stream /api/v1 routes does the MCP NOT
 * reference? verifyMcpRouteTruth only checks the forward direction (referenced
 * paths exist), so it cannot see a capability the MCP never wrapped. This report
 * is advisory (it does not fail the build) - it surfaces drift so new backend
 * endpoints become a reviewable list instead of silent gaps.
 */
export interface ApiCoverage {
  total: number;
  covered: number;
  uncovered: Array<{ method: string; path: string }>;
}

export function computeApiCoverage(params: {
  streamOperations: readonly NormalizedOperation[];
  references: readonly McpPathReference[];
}): ApiCoverage {
  const referenced = new Set(
    params.references.map((r) => canonicalRoutePath(r.path)),
  );
  const intentional = new Set(
    [...INTENTIONALLY_UNWRAPPED_PATHS].map((p) => canonicalRoutePath(p)),
  );
  // A route whose collection prefix IS referenced is almost certainly wrapped
  // via a path helper (e.g. caPath(name, '/crl')) that the static collector
  // cannot reconstruct - treat the prefix as evidence of coverage to avoid
  // false positives. Genuine gaps have no referenced prefix at all.
  const referencedPrefixes = new Set<string>();
  for (const c of referenced) {
    const segs = c.split('/');
    for (let i = 2; i < segs.length; i++) {
      referencedPrefixes.add(segs.slice(0, i).join('/'));
    }
  }
  const apiOps = params.streamOperations.filter((op) =>
    op.path.startsWith('/api/v1'),
  );
  const canonicalPaths = new Set(
    apiOps.map((op) => canonicalRoutePath(op.path)),
  );
  const uncovered: Array<{ method: string; path: string }> = [];
  const seen = new Set<string>();
  for (const op of apiOps) {
    const canonical = canonicalRoutePath(op.path);
    if (referenced.has(canonical)) continue;
    if (intentional.has(canonical)) continue;
    // Skip routes reached through a referenced prefix (helper-built paths).
    const parent = canonical.split('/').slice(0, -1).join('/');
    if (referencedPrefixes.has(parent) || referenced.has(parent)) continue;
    const key = `${op.method} ${canonical}`;
    if (seen.has(key)) continue;
    seen.add(key);
    uncovered.push({ method: op.method, path: op.path });
  }
  const uncoveredPaths = new Set(
    uncovered.map((u) => canonicalRoutePath(u.path)),
  );
  return {
    total: canonicalPaths.size,
    covered: canonicalPaths.size - uncoveredPaths.size,
    uncovered: uncovered.sort(
      (a, b) =>
        a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
    ),
  };
}

function writeJson(path: string, data: unknown): void {
  mkdirSync(resolve(path, '..'), { recursive: true });
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

export function writeTruthArtifacts(params: {
  outputDir: string;
  streamRoot: string;
  references: readonly McpPathReference[];
  streamOperations: readonly NormalizedOperation[];
}): void {
  mkdirSync(params.outputDir, { recursive: true });

  writeJson(join(params.outputDir, 'stream-routes.json'), {
    generatedAt: new Date().toISOString(),
    sourceRoot: params.streamRoot,
    routeCount: params.streamOperations.length,
    routes: params.streamOperations,
  });
  writeJson(join(params.outputDir, 'mcp-api-paths.json'), {
    generatedAt: new Date().toISOString(),
    referenceCount: params.references.length,
    references: params.references,
  });
}
