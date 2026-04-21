import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  isNode,
  walkAst,
  type TypeScriptFactDetectorContext,
} from './shared';

const FETCH_LIKE_CALLEES = new Set([
  'fetch',
  'axios',
  'axios.delete',
  'axios.get',
  'axios.head',
  'axios.options',
  'axios.patch',
  'axios.post',
  'axios.put',
  'axios.request',
]);

const BROWSER_GLOBALS = new Set([
  'document',
  'location',
  'localStorage',
  'navigator',
  'sessionStorage',
  'window',
]);

const NEXT_CLIENT_HOOKS = new Set([
  'usePathname',
  'useRouter',
  'useSearchParams',
  'useSelectedLayoutSegment',
  'useSelectedLayoutSegments',
]);

const SERVER_FILE_PATH_PATTERN = /(^|\/)(app|pages)\//;
const SERVER_LEAF_FILE_PATTERN = /(^|\/)(layout|page|route)\.(ts|tsx|js|jsx)$/;

function hasUseClientDirective(program: TSESTree.Program): boolean {
  const [firstStatement] = program.body;

  return Boolean(
    firstStatement &&
      firstStatement.type === 'ExpressionStatement' &&
      firstStatement.expression.type === 'Literal' &&
      firstStatement.expression.value === 'use client',
  );
}

function isLikelyNextServerFile(path: string): boolean {
  return SERVER_FILE_PATH_PATTERN.test(path) || SERVER_LEAF_FILE_PATTERN.test(path);
}

function isFetchLikeCallText(text: string | undefined): boolean {
  return Boolean(text && FETCH_LIKE_CALLEES.has(text));
}

function collectEffectWaterfallFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'useEffect' && calleeText !== 'React.useEffect') {
      return;
    }

    const callback = node.arguments[0];

    if (
      !callback ||
      (callback.type !== 'ArrowFunctionExpression' &&
        callback.type !== 'FunctionExpression')
    ) {
      return;
    }

    const awaitedFetchCalls: TSESTree.AwaitExpression[] = [];

    walkAst(callback.body as TSESTree.Node, (candidate) => {
      if (candidate.type !== 'AwaitExpression') {
        return;
      }

      const awaited = candidate.argument;

      if (!isNode(awaited) || awaited.type !== 'CallExpression') {
        return;
      }

      const awaitedCalleeText = getCalleeText(
        awaited.callee,
        context.sourceText,
      );

      if (!isFetchLikeCallText(awaitedCalleeText)) {
        return;
      }

      awaitedFetchCalls.push(candidate);
    });

    if (awaitedFetchCalls.length < 2) {
      return;
    }

    const issueNode = awaitedFetchCalls[0];

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: 'performance.react-effect-fetch-waterfall',
        node: issueNode,
        nodeIds: context.nodeIds,
        props: {
          effectHook: calleeText,
          fetchCount: awaitedFetchCalls.length,
        },
        text: getNodeText(issueNode, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectNextBoundaryLeakFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!isLikelyNextServerFile(context.path) || hasUseClientDirective(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];
  let issueNode: TSESTree.Node | undefined;

  walkAst(context.program, (node) => {
    if (issueNode) {
      return;
    }

    if (node.type === 'Identifier' && BROWSER_GLOBALS.has(node.name)) {
      issueNode = node;
      return;
    }

    if (node.type === 'MemberExpression') {
      const rootText = getNodeText(node.object, context.sourceText);

      if (rootText && BROWSER_GLOBALS.has(rootText)) {
        issueNode = node;
      }

      return;
    }

    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (!calleeText) {
        return;
      }

      if (NEXT_CLIENT_HOOKS.has(calleeText) || BROWSER_GLOBALS.has(calleeText)) {
        issueNode = node;
      }
    }

    if (node.type === 'ImportDeclaration') {
      const source = node.source.value;

      if (source !== 'next/navigation' && source !== 'next/router') {
        return;
      }

      const importedNames = node.specifiers
        .map((specifier) => {
          if (specifier.type === 'ImportSpecifier') {
            return specifier.imported.type === 'Identifier'
              ? specifier.imported.name
              : specifier.imported.value;
          }

          if (specifier.type === 'ImportDefaultSpecifier') {
            return specifier.local.name;
          }

          return undefined;
        })
        .filter((name): name is string => Boolean(name));

      if (importedNames.some((name) => NEXT_CLIENT_HOOKS.has(name))) {
        issueNode = node;
      }
    }
  });

  if (!issueNode) {
    return facts;
  }

  facts.push(
    createObservedFact({
      appliesTo: 'file',
      kind: 'framework.next-server-client-boundary-leak',
      node: issueNode,
      nodeIds: context.nodeIds,
      props: {
        filePath: context.path,
      },
      text: getNodeText(issueNode, context.sourceText),
    }),
  );

  return facts;
}

export function detectReactNextBestPracticesFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectEffectWaterfallFacts(context),
    ...collectNextBoundaryLeakFacts(context),
  ];
}

