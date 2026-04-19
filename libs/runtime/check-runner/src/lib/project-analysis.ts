import type {
  AnalyzedFile,
  ObservedFact,
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

interface ProjectAnalysisOptions {
  scopeMode: ProjectAnalysisScopeMode;
}

interface ImportEdge {
  source: string;
  resolvedPath?: string;
  range: ObservedRange;
}

interface FunctionInfo {
  name?: string;
  node: ObservedNode;
  hasDirectIo: boolean;
  duplicateKey?: string;
  lineCount: number;
}

interface RouteEntry {
  path: string;
  range: ObservedRange;
}

interface FrontendRouteCall {
  path: string;
  range: ObservedRange;
}

interface FileContext {
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

const LOOP_NODE_KINDS = new Set([
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

const BACKEND_PATH_PATTERN =
  /(?:^|\/)(api|server|routes?|controllers?|handlers?)(?:\/|$)/i;
const FRONTEND_PATH_PATTERN =
  /(?:^|\/)(app|client|components|frontend|pages|ui|web)(?:\/|$)|\.(tsx|jsx)$/i;
const CRITICAL_PATH_PATTERN =
  /(?:^|\/)(api|server|services?|controllers?|handlers?|core)(?:\/|$)/i;
const CRITICAL_KEYWORD_PATTERN =
  /\b(admin|auth|authorize|billing|owner|ownership|password|payment|payout|refund|session|token|transfer)\b/i;
const AUTH_GUARD_PATTERN =
  /\b(assertAuthorized|authorize|authorized|authGuard|checkPermission|currentUser|ensureAuthorized|hasPermission|isAuthenticated|protect(edRoute)?|req\.user|requireAuth|requirePermission|session\.user|useAuth|verify(Session|Token)|withAuth)\b/;
const OWNERSHIP_GUARD_PATTERN =
  /\b(assertOwner|currentUser\.id\s*===|ensureOwner|isOwner|ownsResource|req\.user\.id\s*===|requireOwnership|session\.user(?:Id)?\s*===|verifyOwnership)\b/;
const SENSITIVE_ACTION_CALL_PATTERN =
  /\b(archive|ban|delete|destroy|exportAll|grant|payout|refund|remove|resetPassword|revoke|setRole|transfer)[A-Za-z0-9_$]*\s*\(/;
const OWNERSHIP_INPUT_PATTERN =
  /\b(?:context|ctx|event|params|req|request)\.(?:body|params|query)\.(?:accountId|organizationId|ownerId|profileId|projectId|userId|workspaceId)\b/;
const DIRECT_IO_CALL_PATTERN =
  /\b(axios\.(delete|get|patch|post|put|request)|client\.query|db\.[A-Za-z_$][A-Za-z0-9_$]*|fetch|httpClient\.[A-Za-z_$][A-Za-z0-9_$]*|pool\.query|prisma\.[A-Za-z_$][A-Za-z0-9_$]*)\s*\(/;

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
      middle + 1 < lineStarts.length ? lineStarts[middle + 1] : Number.MAX_SAFE_INTEGER;

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

function createRangeFromOffsets(
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

function createFileStartRange(file: AnalyzedFile): ObservedRange {
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

function rangeContains(outer: ObservedRange, inner: ObservedRange): boolean {
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

function isTestPath(path: string): boolean {
  return /(?:^|\/)__tests__(?:\/|$)|\.(spec|test)\.[jt]sx?$/i.test(path);
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
  return /\b(batch|bulk|many|all)\b/i.test(name) || /(?:Batch|Bulk|Many|All)$/u.test(name);
}

function isBatchAlternative(candidateName: string, calledName: string): boolean {
  if (candidateName === calledName) {
    return false;
  }

  if (!hasBatchToken(candidateName) && normalizePluralStem(candidateName) === normalizePluralStem(calledName)) {
    return /s$/i.test(candidateName) && !/s$/i.test(calledName);
  }

  return normalizePluralStem(candidateName) === normalizePluralStem(calledName);
}

function normalizeStem(path: string): string {
  return basename(path, extname(path)).replace(/\.(spec|test)$/i, '');
}

function normalizeEndpointPath(path: string): string {
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
  const declarationMatch = /^\s*(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/.exec(
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

function collectRoutes(file: AnalyzedFile, lineStarts: readonly number[]): RouteEntry[] {
  const routes: RouteEntry[] = [];
  const pattern = /\b(?:app|router)\.(?:delete|get|patch|post|put)\(\s*['"]([^'"]+)['"]/g;
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

function createFileContexts(analyzedFiles: readonly AnalyzedFile[]): Map<string, FileContext> {
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

function ensureFacts(file: AnalyzedFile): ObservedFact[] {
  if (!file.semantics) {
    file.semantics = {};
  }

  if (!file.semantics.controlFlow) {
    file.semantics.controlFlow = {
      functions: [],
      blocks: [],
      edges: [],
      facts: [],
    };
  }

  return file.semantics.controlFlow.facts;
}

function appendFact(
  context: FileContext,
  fact: Omit<ObservedFact, 'id'>,
): void {
  const facts = ensureFacts(context.file);
  const factId = [
    'project',
    fact.kind,
    context.file.path,
    fact.range.startLine,
    fact.range.startColumn,
    fact.range.endLine,
    fact.range.endColumn,
  ].join(':');

  if (facts.some((candidate) => candidate.id === factId)) {
    return;
  }

  facts.push({
    ...fact,
    id: factId,
  });
}

function extractSimpleCallName(text: string | undefined): string | undefined {
  if (!text) {
    return undefined;
  }

  const match = /^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/.exec(text);

  return match?.[1];
}

function findCallNodesWithinRange(
  file: AnalyzedFile,
  range: ObservedRange,
): ObservedNode[] {
  return file.nodes.filter(
    (node) => node.kind === 'CallExpression' && rangeContains(range, node.range),
  );
}

function findLoopNodes(file: AnalyzedFile): ObservedNode[] {
  return file.nodes.filter((node) => LOOP_NODE_KINDS.has(node.kind));
}

function findMatchingNode(
  file: AnalyzedFile,
  predicate: (node: ObservedNode) => boolean,
): ObservedNode | undefined {
  return file.nodes.find(predicate);
}

function collectReachableHelperNames(
  context: FileContext,
  fileContexts: ReadonlyMap<string, FileContext>,
): string[] {
  const names = new Set(
    context.functions
      .map((info) => info.name)
      .filter((name): name is string => Boolean(name && name.length > 0)),
  );

  for (const importEdge of context.imports) {
    if (!importEdge.resolvedPath) {
      continue;
    }

    for (const helper of fileContexts.get(importEdge.resolvedPath)?.functions ?? []) {
      if (helper.name) {
        names.add(helper.name);
      }
    }
  }

  return [...names];
}

function helperBodyLooksLikeIo(
  callName: string,
  context: FileContext,
  fileContexts: ReadonlyMap<string, FileContext>,
): boolean {
  if (
    context.functions.some(
      (helper) => helper.name === callName && helper.hasDirectIo,
    )
  ) {
    return true;
  }

  if (
    DIRECT_IO_CALL_PATTERN.test(context.file.text) &&
    new RegExp(
      `\\b(?:async\\s+)?function\\s+${callName}\\s*\\(|\\bconst\\s+${callName}\\s*=`,
      'u',
    ).test(context.file.text)
  ) {
    return true;
  }

  return context.imports.some((importEdge) => {
    if (!importEdge.resolvedPath) {
      return false;
    }

    const importedContext = fileContexts.get(importEdge.resolvedPath);

    if (!importedContext) {
      return false;
    }

    if (
      importedContext.functions.some(
        (helper) => helper.name === callName && helper.hasDirectIo,
      )
    ) {
      return true;
    }

    return (
      DIRECT_IO_CALL_PATTERN.test(importedContext.file.text) &&
      new RegExp(
        `\\b(?:async\\s+)?function\\s+${callName}\\s*\\(|\\bconst\\s+${callName}\\s*=`,
        'u',
      ).test(importedContext.file.text)
    );
  });
}

function forEachSimpleLoopBody(
  context: FileContext,
  callback: (bodyText: string, bodyStartOffset: number) => void,
): void {
  const loopPattern = /\bfor\s*\([^)]*\)\s*\{([\s\S]*?)\}/g;

  for (const match of context.file.text.matchAll(loopPattern)) {
    const matchedText = match[0];
    const bodyText = match[1] ?? '';
    const matchStart = match.index ?? 0;
    const bodyStartInMatch = matchedText.indexOf(bodyText);

    if (bodyStartInMatch < 0) {
      continue;
    }

    callback(bodyText, matchStart + bodyStartInMatch);
  }
}

function isCallToIoHelper(
  callNode: ObservedNode,
  context: FileContext,
  fileContexts: ReadonlyMap<string, FileContext>,
): boolean {
  if (DIRECT_IO_CALL_PATTERN.test(callNode.text ?? '')) {
    return true;
  }

  const callName = extractSimpleCallName(callNode.text);

  if (!callName) {
    return false;
  }

  return helperBodyLooksLikeIo(callName, context, fileContexts);
}

function emitMissingAuthorizationFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    const looksLikeBackend =
      BACKEND_PATH_PATTERN.test(context.file.path) || context.routes.length > 0;

    if (!looksLikeBackend || context.hasAuthGuard) {
      continue;
    }

    const sensitiveCall = findMatchingNode(
      context.file,
      (node) =>
        node.kind === 'CallExpression' &&
        SENSITIVE_ACTION_CALL_PATTERN.test(node.text ?? ''),
    );

    if (!sensitiveCall) {
      continue;
    }

    appendFact(context, {
      kind: 'security.missing-authorization-before-sensitive-action',
      appliesTo: 'function',
      range: sensitiveCall.range,
      text: sensitiveCall.text,
      props: {},
    });
  }
}

function emitMissingOwnershipFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    const looksLikeBackend =
      BACKEND_PATH_PATTERN.test(context.file.path) || context.routes.length > 0;

    if (!looksLikeBackend || !context.hasAuthGuard || context.hasOwnershipGuard) {
      continue;
    }

    const ownershipInputMatch = OWNERSHIP_INPUT_PATTERN.exec(context.file.text);
    const sensitiveCall = findMatchingNode(
      context.file,
      (node) =>
        node.kind === 'CallExpression' &&
        SENSITIVE_ACTION_CALL_PATTERN.test(node.text ?? ''),
    );

    if (!ownershipInputMatch || !sensitiveCall) {
      continue;
    }

    const range = createRangeFromOffsets(
      context,
      ownershipInputMatch.index ?? 0,
      (ownershipInputMatch.index ?? 0) + ownershipInputMatch[0].length,
    );

    appendFact(context, {
      kind: 'security.missing-ownership-validation',
      appliesTo: 'function',
      range,
      text: ownershipInputMatch[0],
      props: {},
    });
  }
}

function emitFrontendOnlyAuthorizationFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const routesByPath = new Map<string, Array<{ context: FileContext; route: RouteEntry }>>();

  for (const context of fileContexts.values()) {
    for (const route of context.routes) {
      const key = normalizeEndpointPath(route.path);
      const entries = routesByPath.get(key) ?? [];
      entries.push({ context, route });
      routesByPath.set(key, entries);
    }
  }

  for (const context of fileContexts.values()) {
    const looksLikeFrontend =
      FRONTEND_PATH_PATTERN.test(context.file.path) || context.frontendCalls.length > 0;

    if (!looksLikeFrontend || !AUTH_GUARD_PATTERN.test(context.file.text)) {
      continue;
    }

    for (const frontendCall of context.frontendCalls) {
      for (const routeEntry of routesByPath.get(frontendCall.path) ?? []) {
        if (routeEntry.context.hasAuthGuard) {
          continue;
        }

        appendFact(routeEntry.context, {
          kind: 'security.frontend-only-authorization',
          appliesTo: 'project',
          range: routeEntry.route.range,
          text: routeEntry.route.path,
          props: {
            frontendPath: context.file.path,
          },
        });
      }
    }
  }
}

function emitRepeatedIoFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    for (const loopNode of findLoopNodes(context.file)) {
      const loopCalls = findCallNodesWithinRange(context.file, loopNode.range);

      for (const callNode of loopCalls) {
        if (!isCallToIoHelper(callNode, context, fileContexts)) {
          continue;
        }

        appendFact(context, {
          kind: 'performance.repeated-io-in-loop',
          appliesTo: 'function',
          range: callNode.range,
          text: callNode.text,
          props: {},
        });
      }
    }

    forEachSimpleLoopBody(context, (bodyText, bodyStartOffset) => {
      const callPattern = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;

      for (const match of bodyText.matchAll(callPattern)) {
        const callName = match[1];
        const callStart = (match.index ?? 0) + bodyStartOffset;

        if (!callName) {
          continue;
        }

        if (
          !DIRECT_IO_CALL_PATTERN.test(match[0]) &&
          !helperBodyLooksLikeIo(callName, context, fileContexts)
        ) {
          continue;
        }

        appendFact(context, {
          kind: 'performance.repeated-io-in-loop',
          appliesTo: 'function',
          range: createRangeFromOffsets(
            context,
            callStart,
            callStart + match[0].length,
          ),
          text: match[0].trim(),
          props: {},
        });
      }
    });
  }
}

function emitMissingBatchFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    const reachableHelperNames = collectReachableHelperNames(context, fileContexts);

    for (const loopNode of findLoopNodes(context.file)) {
      const loopCalls = findCallNodesWithinRange(context.file, loopNode.range);

      for (const callNode of loopCalls) {
        const calledName = extractSimpleCallName(callNode.text);

        if (!calledName) {
          continue;
        }

        const batchHelperName = reachableHelperNames.find((candidateName) =>
          isBatchAlternative(candidateName, calledName),
        );

        if (!batchHelperName) {
          continue;
        }

        appendFact(context, {
          kind: 'performance.missing-batch-operations',
          appliesTo: 'function',
          range: callNode.range,
          text: callNode.text,
          props: {
            batchHelperName,
          },
        });
      }
    }

    forEachSimpleLoopBody(context, (bodyText, bodyStartOffset) => {
      const callPattern = /\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g;

      for (const match of bodyText.matchAll(callPattern)) {
        const calledName = match[1];

        if (!calledName) {
          continue;
        }

        const batchHelperName = reachableHelperNames.find((candidateName) =>
          isBatchAlternative(candidateName, calledName),
        );

        if (!batchHelperName) {
          continue;
        }

        const callStart = (match.index ?? 0) + bodyStartOffset;

        appendFact(context, {
          kind: 'performance.missing-batch-operations',
          appliesTo: 'function',
          range: createRangeFromOffsets(
            context,
            callStart,
            callStart + match[0].length,
          ),
          text: match[0].trim(),
          props: {
            batchHelperName,
          },
        });
      }
    });
  }
}

function emitDuplicateCodeFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const duplicates = new Map<string, Array<{ context: FileContext; info: FunctionInfo }>>();

  for (const context of fileContexts.values()) {
    if (context.isTestFile) {
      continue;
    }

    for (const info of context.functions) {
      if (!info.duplicateKey) {
        continue;
      }

      const entries = duplicates.get(info.duplicateKey) ?? [];
      entries.push({ context, info });
      duplicates.set(info.duplicateKey, entries);
    }
  }

  for (const entries of duplicates.values()) {
    const distinctPaths = new Set(entries.map((entry) => entry.context.file.path));

    if (distinctPaths.size < 2) {
      continue;
    }

    for (const entry of entries) {
      appendFact(entry.context, {
        kind: 'quality.duplicate-code-block',
        appliesTo: 'file',
        range: entry.info.node.range,
        text: entry.info.name ?? 'duplicated function body',
        props: {
          duplicateCount: distinctPaths.size,
        },
      });
    }
  }
}

function emitTightCouplingFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    for (const importEdge of context.imports) {
      const importedPath = importEdge.resolvedPath;

      if (!importedPath) {
        continue;
      }

      const importedContext = fileContexts.get(importedPath);

      if (!importedContext) {
        continue;
      }

      const returnEdge = importedContext.imports.find(
        (candidate) => candidate.resolvedPath === context.file.path,
      );

      if (!returnEdge) {
        continue;
      }

      appendFact(context, {
        kind: 'quality.tight-module-coupling',
        appliesTo: 'project',
        range: importEdge.range,
        text: importEdge.source,
        props: {
          peerPath: importedPath,
        },
      });

      appendFact(importedContext, {
        kind: 'quality.tight-module-coupling',
        appliesTo: 'project',
        range: returnEdge.range,
        text: returnEdge.source,
        props: {
          peerPath: context.file.path,
        },
      });
    }
  }
}

function emitMissingTestsFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const testStems = new Set(
    [...fileContexts.values()]
      .filter((context) => context.isTestFile)
      .map((context) => normalizeStem(context.file.path)),
  );

  for (const context of fileContexts.values()) {
    if (
      context.isTestFile ||
      !CRITICAL_PATH_PATTERN.test(context.file.path) ||
      !CRITICAL_KEYWORD_PATTERN.test(context.file.text)
    ) {
      continue;
    }

    if (testStems.has(normalizeStem(context.file.path))) {
      continue;
    }

    appendFact(context, {
      kind: 'quality.missing-tests-for-critical-logic',
      appliesTo: 'project',
      range: createFileStartRange(context.file),
      text: basename(context.file.path),
      props: {},
    });
  }
}

function emitLogicChangeWithoutTestsFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const changedTestStems = new Set(
    [...fileContexts.values()]
      .filter(
        (context) =>
          context.isTestFile &&
          Boolean(context.file.changedRanges && context.file.changedRanges.length > 0),
      )
      .map((context) => normalizeStem(context.file.path)),
  );

  for (const context of fileContexts.values()) {
    if (
      context.isTestFile ||
      !context.file.changedRanges ||
      context.file.changedRanges.length === 0 ||
      !CRITICAL_PATH_PATTERN.test(context.file.path) ||
      !CRITICAL_KEYWORD_PATTERN.test(context.file.text)
    ) {
      continue;
    }

    if (changedTestStems.has(normalizeStem(context.file.path))) {
      continue;
    }

    appendFact(context, {
      kind: 'quality.logic-change-without-test-updates',
      appliesTo: 'project',
      range: context.file.changedRanges[0],
      text: basename(context.file.path),
      props: {},
    });
  }
}

export function augmentProjectFacts(
  analyzedFiles: readonly AnalyzedFile[],
  options: ProjectAnalysisOptions,
): AnalyzedFile[] {
  const contexts = createFileContexts(analyzedFiles);

  emitMissingAuthorizationFacts(contexts);
  emitMissingOwnershipFacts(contexts);
  emitFrontendOnlyAuthorizationFacts(contexts);
  emitRepeatedIoFacts(contexts);
  emitMissingBatchFacts(contexts);
  emitDuplicateCodeFacts(contexts);
  emitTightCouplingFacts(contexts);
  emitMissingTestsFacts(contexts);

  if (options.scopeMode === 'diff') {
    emitLogicChangeWithoutTestsFacts(contexts);
  }

  return [...analyzedFiles];
}
