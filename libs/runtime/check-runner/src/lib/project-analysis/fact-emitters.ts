import type {
  AnalyzedFile,
  ObservedFact,
  ObservedNode,
  ObservedRange,
} from '@critiq/core-rules-engine';
import { basename, dirname } from 'node:path/posix';

import {
  AUTH_GUARD_PATTERN,
  BACKEND_PATH_PATTERN,
  CRITICAL_KEYWORD_PATTERN,
  CRITICAL_PATH_PATTERN,
  DIRECT_IO_CALL_PATTERN,
  FRONTEND_PATH_PATTERN,
  LOOP_NODE_KINDS,
  OWNERSHIP_INPUT_PATTERN,
  SENSITIVE_ACTION_CALL_PATTERN,
  createFileStartRange,
  createRangeFromOffsets,
  isBatchAlternative,
  isFixtureLikePath,
  isTestPath,
  matchingTestPathsForSource,
  normalizeEndpointPath,
  rangeContains,
  rangeOverlaps,
  type FileContext,
  type FunctionInfo,
  type RouteEntry,
} from './context';

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

    for (const helper of fileContexts.get(importEdge.resolvedPath)?.functions ??
      []) {
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

export function emitMissingAuthorizationFacts(
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

export function emitMissingOwnershipFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    const looksLikeBackend =
      BACKEND_PATH_PATTERN.test(context.file.path) || context.routes.length > 0;

    if (
      !looksLikeBackend ||
      !context.hasAuthGuard ||
      context.hasOwnershipGuard
    ) {
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

export function emitFrontendOnlyAuthorizationFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const routesByPath = new Map<
    string,
    Array<{ context: FileContext; route: RouteEntry }>
  >();

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
      FRONTEND_PATH_PATTERN.test(context.file.path) ||
      context.frontendCalls.length > 0;

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

export function emitRepeatedIoFacts(
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

export function emitMissingBatchFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    const reachableHelperNames = collectReachableHelperNames(
      context,
      fileContexts,
    );

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

export function emitDuplicateCodeFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const duplicates = new Map<
    string,
    Array<{ context: FileContext; info: FunctionInfo }>
  >();

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
    const distinctPaths = new Set(
      entries.map((entry) => entry.context.file.path),
    );

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

export function emitTightCouplingFacts(
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

const EXPORT_DECLARATION_PATTERN =
  /^\s*export\s+(?:const|let|var|function|class|type|interface|enum)\s+([A-Za-z_$][A-Za-z0-9_$]*)/gm;
const EXPORT_SPECIFIER_PATTERN = /^\s*export\s*\{\s*([^}]+)\s*\}/gm;
const REEXPORT_PATTERN = /^\s*export\s+\*\s+from\s+['"][^'"]+['"]/gm;

function collectExportedNames(sourceText: string): string[] {
  const names: string[] = [];
  let match: RegExpExecArray | null = EXPORT_DECLARATION_PATTERN.exec(sourceText);
  while (match !== null) {
    if (match[1]) {
      names.push(match[1]);
    }
    match = EXPORT_DECLARATION_PATTERN.exec(sourceText);
  }

  match = EXPORT_SPECIFIER_PATTERN.exec(sourceText);
  while (match !== null) {
    const list = match[1] ?? '';
    for (const raw of list.split(',')) {
      const candidate = raw.trim().split(/\s+as\s+/i)[0]?.trim();
      if (candidate) {
        names.push(candidate);
      }
    }
    match = EXPORT_SPECIFIER_PATTERN.exec(sourceText);
  }

  return names;
}

function isBarrelFile(sourceText: string): boolean {
  const reexportCount = [...sourceText.matchAll(REEXPORT_PATTERN)].length;
  const exportNames = collectExportedNames(sourceText).length;
  return reexportCount >= 2 || (reexportCount >= 1 && exportNames === 0);
}

export function emitWidePublicSurfaceFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    if (context.isTestFile || isFixtureLikePath(context.file.path)) {
      continue;
    }
    const exports = collectExportedNames(context.file.text);
    if (exports.length < 8) {
      continue;
    }
    appendFact(context, {
      kind: 'quality.wide-public-surface',
      appliesTo: 'project',
      range: createFileStartRange(context.file),
      text: basename(context.file.path),
      props: {
        exportCount: exports.length,
      },
    });
  }
}

export function emitBarrelCycleFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    if (!isBarrelFile(context.file.text)) {
      continue;
    }
    for (const edge of context.imports) {
      const resolved = edge.resolvedPath;
      if (!resolved) {
        continue;
      }
      const peer = fileContexts.get(resolved);
      if (!peer || !isBarrelFile(peer.file.text)) {
        continue;
      }
      const hasBackEdge = peer.imports.some(
        (candidate) => candidate.resolvedPath === context.file.path,
      );
      const contextBase = basename(context.file.path).replace(/\.[^.]+$/u, '');
      const peerBase = basename(peer.file.path).replace(/\.[^.]+$/u, '');
      const contextReexportsPeer = new RegExp(
        `export\\s+\\*\\s+from\\s+['"][^'"]*${peerBase}['"]`,
      ).test(context.file.text);
      const peerReexportsContext = new RegExp(
        `export\\s+\\*\\s+from\\s+['"][^'"]*${contextBase}['"]`,
      ).test(peer.file.text);
      if (!hasBackEdge && !(contextReexportsPeer && peerReexportsContext)) {
        continue;
      }
      appendFact(context, {
        kind: 'quality.barrel-file-cycle',
        appliesTo: 'project',
        range: edge.range,
        text: edge.source,
        props: {
          peerPath: peer.file.path,
        },
      });
    }
  }
}

export function emitDeadExportFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const corpus = [...fileContexts.values()]
    .map((context) => context.file.text)
    .join('\n');
  for (const context of fileContexts.values()) {
    if (context.isTestFile || isFixtureLikePath(context.file.path)) {
      continue;
    }
    for (const name of collectExportedNames(context.file.text)) {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const references = new RegExp(`\\b${escaped}\\b`, 'g');
      const hits = [...corpus.matchAll(references)].length;
      if (hits > 1) {
        continue;
      }
      appendFact(context, {
        kind: 'quality.dead-export',
        appliesTo: 'project',
        range: createFileStartRange(context.file),
        text: name,
        props: {},
      });
    }
  }
}

const BRANCH_HEAVY_NODE_KINDS = new Set([
  'IfStatement',
  'ConditionalExpression',
  'SwitchStatement',
]);

const PRODUCTION_TEST_ENV_PATTERN =
  /process\.env\.NODE_ENV\s*===\s*['"]test['"]|import\.meta\.env\.MODE\s*===\s*['"]test['"]|\bimport\.meta\.vitest\b/g;

function countBranchNodesTouchingChanges(
  file: AnalyzedFile,
  changedRanges: readonly ObservedRange[],
): number {
  let count = 0;

  for (const node of file.nodes) {
    if (!BRANCH_HEAVY_NODE_KINDS.has(node.kind)) {
      continue;
    }

    if (!changedRanges.some((range) => rangeOverlaps(range, node.range))) {
      continue;
    }

    count += 1;
  }

  return count;
}

function productionImportLooksTestOnly(resolvedPath: string): boolean {
  return (
    isTestPath(resolvedPath) ||
    /\/__mocks__\//.test(resolvedPath) ||
    /\.(?:spec|test)\.[jt]s$/i.test(resolvedPath)
  );
}

export function emitMissingEdgeCaseTestsFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
  availableChangedTestPaths: ReadonlySet<string> = new Set(),
): void {
  const changedTestPaths = new Set(
    [
      ...availableChangedTestPaths,
      ...[...fileContexts.values()]
        .filter(
          (context) =>
            context.isTestFile &&
            Boolean(
              context.file.changedRanges && context.file.changedRanges.length > 0,
            ),
        )
        .map((context) => context.file.path),
    ],
  );

  for (const context of fileContexts.values()) {
    const changedRanges = context.file.changedRanges;

    if (
      context.isTestFile ||
      isFixtureLikePath(context.file.path) ||
      !changedRanges ||
      changedRanges.length === 0 ||
      !CRITICAL_PATH_PATTERN.test(context.file.path)
    ) {
      continue;
    }

    if (countBranchNodesTouchingChanges(context.file, changedRanges) < 5) {
      continue;
    }

    if (
      matchingTestPathsForSource(context.file.path).some((path) =>
        changedTestPaths.has(path),
      )
    ) {
      continue;
    }

    appendFact(context, {
      kind: 'testing.missing-edge-case-tests-for-changes',
      appliesTo: 'project',
      range: changedRanges[0],
      text: basename(context.file.path),
      props: {},
    });
  }
}

export function emitProductionTestBoundaryFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  for (const context of fileContexts.values()) {
    if (context.isTestFile || isFixtureLikePath(context.file.path)) {
      continue;
    }

    const text = context.file.text;
    const pattern = new RegExp(PRODUCTION_TEST_ENV_PATTERN.source, 'g');
    let environmentMatch: RegExpExecArray | null = pattern.exec(text);

    while (environmentMatch !== null) {
      const startOffset = environmentMatch.index;
      const endOffset = startOffset + environmentMatch[0].length;

      appendFact(context, {
        kind: 'testing.test-only-env-branch-in-production',
        appliesTo: 'project',
        range: createRangeFromOffsets(context, startOffset, endOffset),
        text: environmentMatch[0].trim(),
        props: {},
      });

      environmentMatch = pattern.exec(text);
    }

    for (const importEdge of context.imports) {
      const resolved = importEdge.resolvedPath;

      if (!resolved || !productionImportLooksTestOnly(resolved)) {
        continue;
      }

      appendFact(context, {
        kind: 'testing.production-imports-test-code',
        appliesTo: 'project',
        range: importEdge.range,
        text: importEdge.source,
        props: {
          resolvedPath: resolved,
        },
      });
    }
  }
}

export function emitMissingTestsFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
  availableTestPaths: ReadonlySet<string> = new Set(),
): void {
  const testPaths = new Set(
    [
      ...availableTestPaths,
      ...[...fileContexts.values()]
        .filter((context) => context.isTestFile)
        .map((context) => context.file.path),
    ],
  );

  for (const context of fileContexts.values()) {
    if (
      context.isTestFile ||
      isFixtureLikePath(context.file.path) ||
      !CRITICAL_PATH_PATTERN.test(context.file.path) ||
      !CRITICAL_KEYWORD_PATTERN.test(context.file.text)
    ) {
      continue;
    }

    if (
      matchingTestPathsForSource(context.file.path).some((path) =>
        testPaths.has(path),
      )
    ) {
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

const NEXT_APP_ROUTE_FILE_PATTERN =
  /(?:^|\/)app\/(?:.+\/)?(?:page|layout)\.(?:tsx|jsx|ts|js)$/u;

export function emitMissingNextErrorBoundaryFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
): void {
  const paths = new Set(fileContexts.keys());

  for (const context of fileContexts.values()) {
    const filePath = context.file.path;

    if (!NEXT_APP_ROUTE_FILE_PATTERN.test(filePath)) {
      continue;
    }

    const directory = dirname(filePath);
    const hasLocalErrorFile = [
      `${directory}/error.tsx`,
      `${directory}/error.ts`,
      `${directory}/error.jsx`,
      `${directory}/error.js`,
    ].some((candidate) => paths.has(candidate));

    if (hasLocalErrorFile) {
      continue;
    }

    appendFact(context, {
      kind: 'ui.react.missing-error-boundary',
      appliesTo: 'project',
      range: createFileStartRange(context.file),
      text: basename(filePath),
      props: {
        routeDirectory: directory,
      },
    });
  }
}

export function emitLogicChangeWithoutTestsFacts(
  fileContexts: ReadonlyMap<string, FileContext>,
  availableChangedTestPaths: ReadonlySet<string> = new Set(),
): void {
  const changedTestPaths = new Set(
    [
      ...availableChangedTestPaths,
      ...[...fileContexts.values()]
        .filter(
          (context) =>
            context.isTestFile &&
            Boolean(
              context.file.changedRanges && context.file.changedRanges.length > 0,
            ),
        )
        .map((context) => context.file.path),
    ],
  );

  for (const context of fileContexts.values()) {
    if (
      context.isTestFile ||
      isFixtureLikePath(context.file.path) ||
      !context.file.changedRanges ||
      context.file.changedRanges.length === 0 ||
      !CRITICAL_PATH_PATTERN.test(context.file.path) ||
      !CRITICAL_KEYWORD_PATTERN.test(context.file.text)
    ) {
      continue;
    }

    if (
      matchingTestPathsForSource(context.file.path).some((path) =>
        changedTestPaths.has(path),
      )
    ) {
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
