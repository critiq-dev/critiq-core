import type {
  AnalyzedFile,
  ObservedNode,
  ObservedRange,
} from '@critiq/core-rules-engine';
import {
  basename,
  dirname,
  extname,
  join,
  normalize,
} from 'node:path/posix';

export type ProjectAnalysisScopeMode = 'repo' | 'diff';

export interface ProjectAnalysisOptions {
  scopeMode: ProjectAnalysisScopeMode;
  availableTestPaths?: ReadonlySet<string>;
  availableChangedTestPaths?: ReadonlySet<string>;
}

export interface ImportEdge {
  source: string;
  resolvedPath?: string;
  range: ObservedRange;
}

export interface FunctionInfo {
  name?: string;
  node: ObservedNode;
  hasDirectIo: boolean;
  duplicateKey?: string;
  lineCount: number;
}

export interface RouteEntry {
  path: string;
  range: ObservedRange;
}

export interface FrontendRouteCall {
  path: string;
  range: ObservedRange;
}

export interface FileContext {
  file: AnalyzedFile;
  lineStarts: number[];
  nodeMap: Map<string, ObservedNode>;
  functions: FunctionInfo[];
  imports: ImportEdge[];
  routes: RouteEntry[];
  frontendCalls: FrontendRouteCall[];
  isTestFile: boolean;
  hasAuthGuard: boolean;
  hasOwnershipGuard: boolean;
}

export const LOOP_NODE_KINDS = new Set([
  'ForStatement',
  'ForInStatement',
  'ForOfStatement',
  'WhileStatement',
  'DoWhileStatement',
]);

const FUNCTION_NODE_KINDS = new Set([
  'FunctionDeclaration',
  'FunctionExpression',
  'ArrowFunctionExpression',
]);

export const BACKEND_PATH_PATTERN =
  /(?:^|\/)(api|server|routes?|controllers?|handlers?)(?:\/|$)/i;
export const FRONTEND_PATH_PATTERN =
  /(?:^|\/)(app|client|components|frontend|pages|ui|web)(?:\/|$)|\.(tsx|jsx)$/i;
export const CRITICAL_PATH_PATTERN =
  /(?:^|\/)(api|server|services?|controllers?|handlers?|core)(?:\/|$)/i;
export const CRITICAL_KEYWORD_PATTERN =
  /\b(admin|auth|authorize|billing|owner|ownership|password|payment|payout|refund|session|token|transfer)\b/i;
export const AUTH_GUARD_PATTERN =
  /\b(assertAuthorized|authorize|authorized|authGuard|checkPermission|currentUser|ensureAuthorized|hasPermission|isAuthenticated|protect(edRoute)?|req\.user|requireAuth|requirePermission|session\.user|useAuth|verify(Session|Token)|withAuth)\b/;
export const OWNERSHIP_GUARD_PATTERN =
  /\b(assertOwner|currentUser\.id\s*===|ensureOwner|isOwner|ownsResource|req\.user\.id\s*===|requireOwnership|session\.user(?:Id)?\s*===|verifyOwnership)\b/;
export const SENSITIVE_ACTION_CALL_PATTERN =
  /\b(archive|ban|delete|destroy|exportAll|grant|payout|refund|remove|resetPassword|revoke|setRole|transfer)[A-Za-z0-9_$]*\s*\(/;
export const OWNERSHIP_INPUT_PATTERN =
  /\b(?:context|ctx|event|params|req|request)\.(?:body|params|query)\.(?:accountId|organizationId|ownerId|profileId|projectId|userId|workspaceId)\b/;
export const DIRECT_IO_CALL_PATTERN =
  /\b(axios\.(delete|get|patch|post|put|request)|client\.query|db\.[A-Za-z_$][A-Za-z0-9_$]*|fetch|httpClient\.[A-Za-z_$][A-Za-z0-9_$]*|pool\.query|prisma\.[A-Za-z_$][A-Za-z0-9_$]*)\s*\(/;
const FIXTURE_LIKE_PATH_PATTERN =
  /(?:^|\/)(?:__data__|__fixtures__|__mocks__|fixtures?|mocks?|test-data|testdata)(?:\/|$)/i;
const TEST_CONTAINER_DIRECTORY_PATTERN =
  /^__(?:tests|fixtures|mocks|data)__$/i;
const supportedTestExtensions = ['.js', '.jsx', '.ts', '.tsx'] as const;

function buildLineStarts(text: string): number[] {
  const lineStarts = [0];

  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      lineStarts.push(index + 1);
    }
  }

  return lineStarts;
}

function offsetToLineColumn(
  lineStarts: readonly number[],
  offset: number,
): { line: number; column: number } {
  let low = 0;
  let high = lineStarts.length - 1;

  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const lineStart = lineStarts[middle];
    const nextLineStart =
      middle + 1 < lineStarts.length
        ? lineStarts[middle + 1]
        : Number.MAX_SAFE_INTEGER;

    if (offset < lineStart) {
      high = middle - 1;
      continue;
    }

    if (offset >= nextLineStart) {
      low = middle + 1;
      continue;
    }

    return {
      line: middle + 1,
      column: offset - lineStart + 1,
    };
  }

  return {
    line: 1,
    column: 1,
  };
}

export function createRangeFromOffsets(
  context: FileContext,
  startOffset: number,
  endOffset: number,
): ObservedRange {
  const safeEndOffset = Math.max(startOffset + 1, endOffset);
  const start = offsetToLineColumn(context.lineStarts, startOffset);
  const end = offsetToLineColumn(context.lineStarts, safeEndOffset);

  return {
    startLine: start.line,
    startColumn: start.column,
    endLine: end.line,
    endColumn: end.column,
  };
}

export function createFileStartRange(file: AnalyzedFile): ObservedRange {
  const firstLine = file.text.split(/\r?\n/, 1)[0] ?? '';

  return {
    startLine: 1,
    startColumn: 1,
    endLine: 1,
    endColumn: Math.max(1, firstLine.length + 1),
  };
}

function compareRanges(left: ObservedRange, right: ObservedRange): number {
  if (left.startLine !== right.startLine) {
    return left.startLine - right.startLine;
  }

  if (left.startColumn !== right.startColumn) {
    return left.startColumn - right.startColumn;
  }

  if (left.endLine !== right.endLine) {
    return left.endLine - right.endLine;
  }

  return left.endColumn - right.endColumn;
}

export function rangeContains(
  outer: ObservedRange,
  inner: ObservedRange,
): boolean {
  return (
    compareRanges(outer, {
      startLine: inner.startLine,
      startColumn: inner.startColumn,
      endLine: inner.startLine,
      endColumn: inner.startColumn,
    }) <= 0 &&
    compareRanges(
      {
        startLine: inner.endLine,
        startColumn: inner.endColumn,
        endLine: inner.endLine,
        endColumn: inner.endColumn,
      },
      outer,
    ) <= 0
  );
}

export function isTestPath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|spec|test|tests)(?:\/|$)|\.(spec|test)\.(?:[jt]sx?|java|php|py|rb|rs)$/i.test(
    path,
  );
}

function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\n]*/g, ' ');
}

function normalizeDuplicateBody(text: string): string {
  return stripComments(text)
    .replace(/\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*/g, 'function')
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizePluralStem(name: string): string {
  return name
    .toLowerCase()
    .replace(/(batch|bulk|many|all)/g, '')
    .replace(/ies$/g, 'y')
    .replace(/s$/g, '');
}

function hasBatchToken(name: string): boolean {
  return (
    /\b(batch|bulk|many|all)\b/i.test(name) ||
    /(?:Batch|Bulk|Many|All)$/u.test(name)
  );
}

export function isBatchAlternative(
  candidateName: string,
  calledName: string,
): boolean {
  if (candidateName === calledName) {
    return false;
  }

  if (
    !hasBatchToken(candidateName) &&
    normalizePluralStem(candidateName) === normalizePluralStem(calledName)
  ) {
    return /s$/i.test(candidateName) && !/s$/i.test(calledName);
  }

  return normalizePluralStem(candidateName) === normalizePluralStem(calledName);
}

export function normalizeStem(path: string): string {
  const rawStem = basename(path, extname(path)).replace(/\.(spec|test)$/i, '');

  if (rawStem.toLowerCase() !== 'index') {
    return rawStem;
  }

  let currentDirectory = dirname(path);
  let directoryStem = basename(currentDirectory);

  if (TEST_CONTAINER_DIRECTORY_PATTERN.test(directoryStem)) {
    currentDirectory = dirname(currentDirectory);
    directoryStem = basename(currentDirectory);
  }

  return directoryStem || rawStem;
}

export function isFixtureLikePath(path: string): boolean {
  return FIXTURE_LIKE_PATH_PATTERN.test(path);
}

export function matchingTestPathsForSource(sourcePath: string): string[] {
  const sourceDirectory = dirname(sourcePath);
  const rawStem = basename(sourcePath, extname(sourcePath)).replace(/\.(spec|test)$/i, '');
  const normalizedStem = normalizeStem(sourcePath);
  const stems = new Set([rawStem, normalizedStem]);
  const directories = new Set([
    sourceDirectory,
    join(sourceDirectory, '__tests__'),
  ]);

  if (rawStem.toLowerCase() === 'index' || normalizedStem !== rawStem) {
    const parentDirectory = dirname(sourceDirectory);
    directories.add(parentDirectory);
    directories.add(join(parentDirectory, '__tests__'));
  }

  const paths: string[] = [];

  for (const directory of directories) {
    for (const stem of stems) {
      for (const extension of supportedTestExtensions) {
        paths.push(join(directory, `${stem}.spec${extension}`));
        paths.push(join(directory, `${stem}.test${extension}`));
      }
    }
  }

  return [...new Set(paths)];
}

export function normalizeEndpointPath(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    try {
      return new URL(path).pathname.replace(/\/+$/, '') || '/';
    } catch {
      return path.replace(/\/+$/, '') || '/';
    }
  }

  return path.replace(/\/+$/, '') || '/';
}

function resolveLocalModulePath(
  sourcePath: string,
  specifier: string,
  knownPaths: ReadonlySet<string>,
): string | undefined {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) {
    return undefined;
  }

  const basePath = normalize(join(dirname(sourcePath), specifier));
  const candidates = [
    basePath,
    `${basePath}.ts`,
    `${basePath}.tsx`,
    `${basePath}.js`,
    `${basePath}.jsx`,
    join(basePath, 'index.ts'),
    join(basePath, 'index.tsx'),
    join(basePath, 'index.js'),
    join(basePath, 'index.jsx'),
  ];

  return candidates.find((candidate) => knownPaths.has(candidate));
}

function createNodeMap(file: AnalyzedFile): Map<string, ObservedNode> {
  return new Map(file.nodes.map((node) => [node.id, node]));
}

function getChildNodes(
  node: ObservedNode,
  nodeMap: ReadonlyMap<string, ObservedNode>,
): ObservedNode[] {
  return (node.childrenIds ?? [])
    .map((childId) => nodeMap.get(childId))
    .filter((child): child is ObservedNode => Boolean(child));
}

function getFirstNamedChild(
  node: ObservedNode,
  nodeMap: ReadonlyMap<string, ObservedNode>,
): ObservedNode | undefined {
  return getChildNodes(node, nodeMap).find(
    (child) => child.kind === 'Identifier' || child.kind === 'Literal',
  );
}

function inferFunctionName(
  node: ObservedNode,
  nodeMap: ReadonlyMap<string, ObservedNode>,
): string | undefined {
  const declarationMatch =
    /^\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/.exec(
      node.text ?? '',
    );

  if (declarationMatch?.[1]) {
    return declarationMatch[1];
  }

  const directName = getFirstNamedChild(node, nodeMap)?.text?.trim();

  if (directName) {
    return directName;
  }

  const parent = node.parentId ? nodeMap.get(node.parentId) : undefined;

  if (!parent) {
    return undefined;
  }

  if (parent.kind === 'VariableDeclarator') {
    return getFirstNamedChild(parent, nodeMap)?.text?.trim();
  }

  if (parent.kind === 'Property' || parent.kind === 'MethodDefinition') {
    return getFirstNamedChild(parent, nodeMap)?.text?.trim();
  }

  return undefined;
}

function collectFunctions(
  file: AnalyzedFile,
  nodeMap: ReadonlyMap<string, ObservedNode>,
): FunctionInfo[] {
  return file.nodes
    .filter((node) => FUNCTION_NODE_KINDS.has(node.kind))
    .map((node) => {
      const text = node.text ?? '';
      const duplicateKey = normalizeDuplicateBody(text);

      return {
        name: inferFunctionName(node, nodeMap),
        node,
        hasDirectIo: DIRECT_IO_CALL_PATTERN.test(text),
        duplicateKey:
          duplicateKey.length >= 220 &&
          node.range.endLine - node.range.startLine + 1 >= 7
            ? duplicateKey
            : undefined,
        lineCount: node.range.endLine - node.range.startLine + 1,
      };
    });
}

function collectImportEdges(
  file: AnalyzedFile,
  lineStarts: readonly number[],
  knownPaths: ReadonlySet<string>,
): ImportEdge[] {
  const imports: ImportEdge[] = [];
  const patterns = [
    /\b(?:import|export)\b[\s\S]*?\bfrom\s+['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];

  for (const pattern of patterns) {
    for (const match of file.text.matchAll(pattern)) {
      const [matchedText, specifier] = match;
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + matchedText.length;
      const context: FileContext = {
        file,
        lineStarts: [...lineStarts],
        nodeMap: new Map(),
        functions: [],
        imports: [],
        routes: [],
        frontendCalls: [],
        isTestFile: false,
        hasAuthGuard: false,
        hasOwnershipGuard: false,
      };

      imports.push({
        source: specifier,
        resolvedPath: resolveLocalModulePath(file.path, specifier, knownPaths),
        range: createRangeFromOffsets(context, startOffset, endOffset),
      });
    }
  }

  return imports;
}

function collectRoutes(
  file: AnalyzedFile,
  lineStarts: readonly number[],
): RouteEntry[] {
  const routes: RouteEntry[] = [];
  const pattern =
    /\b(?:app|router)\.(?:delete|get|patch|post|put)\(\s*['"]([^'"]+)['"]/g;
  const context: FileContext = {
    file,
    lineStarts: [...lineStarts],
    nodeMap: new Map(),
    functions: [],
    imports: [],
    routes: [],
    frontendCalls: [],
    isTestFile: false,
    hasAuthGuard: false,
    hasOwnershipGuard: false,
  };

  for (const match of file.text.matchAll(pattern)) {
    const [matchedText, routePath] = match;
    const startOffset = match.index ?? 0;
    const endOffset = startOffset + matchedText.length;

    routes.push({
      path: normalizeEndpointPath(routePath),
      range: createRangeFromOffsets(context, startOffset, endOffset),
    });
  }

  return routes;
}

function collectFrontendCalls(
  file: AnalyzedFile,
  lineStarts: readonly number[],
): FrontendRouteCall[] {
  const calls: FrontendRouteCall[] = [];
  const patterns = [
    /\bfetch\(\s*['"]([^'"]+)['"]/g,
    /\baxios\.(?:delete|get|patch|post|put)\(\s*['"]([^'"]+)['"]/g,
  ];
  const context: FileContext = {
    file,
    lineStarts: [...lineStarts],
    nodeMap: new Map(),
    functions: [],
    imports: [],
    routes: [],
    frontendCalls: [],
    isTestFile: false,
    hasAuthGuard: false,
    hasOwnershipGuard: false,
  };

  for (const pattern of patterns) {
    for (const match of file.text.matchAll(pattern)) {
      const [matchedText, routePath] = match;
      const startOffset = match.index ?? 0;
      const endOffset = startOffset + matchedText.length;

      calls.push({
        path: normalizeEndpointPath(routePath),
        range: createRangeFromOffsets(context, startOffset, endOffset),
      });
    }
  }

  return calls;
}

export function createFileContexts(
  analyzedFiles: readonly AnalyzedFile[],
): Map<string, FileContext> {
  const knownPaths = new Set(analyzedFiles.map((file) => file.path));

  return new Map(
    analyzedFiles.map((file) => {
      const lineStarts = buildLineStarts(file.text);
      const nodeMap = createNodeMap(file);
      const context: FileContext = {
        file,
        lineStarts,
        nodeMap,
        functions: collectFunctions(file, nodeMap),
        imports: collectImportEdges(file, lineStarts, knownPaths),
        routes: collectRoutes(file, lineStarts),
        frontendCalls: collectFrontendCalls(file, lineStarts),
        isTestFile: isTestPath(file.path),
        hasAuthGuard: AUTH_GUARD_PATTERN.test(file.text),
        hasOwnershipGuard: OWNERSHIP_GUARD_PATTERN.test(file.text),
      };

      return [file.path, context];
    }),
  );
}
