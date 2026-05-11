import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
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

function effectUsesDataLoadingPrimitives(bodyText: string): boolean {
  return (
    /\buseSWR\b/u.test(bodyText) ||
    /\buseQuery\b/u.test(bodyText) ||
    /\buseInfiniteQuery\b/u.test(bodyText) ||
    /\buseMutation\b/u.test(bodyText) ||
    /\bpreloadQuery\b/u.test(bodyText) ||
    /\bfetchQuery\b/u.test(bodyText)
  );
}

function networkCallUsesAbortSignal(
  call: TSESTree.CallExpression,
): boolean {
  for (const argument of call.arguments) {
    if (argument.type === 'ObjectExpression') {
      if (getObjectProperty(argument, 'signal')) {
        return true;
      }
    }
  }

  return false;
}

function collectUnsafeFetchCallsInEffectBody(
  effectBody: TSESTree.Node,
  sourceText: string,
): TSESTree.CallExpression[] {
  const unsafe: TSESTree.CallExpression[] = [];

  walkAst(effectBody, (candidate: TSESTree.Node) => {
    if (candidate.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(candidate.callee, sourceText);

    if (!isFetchLikeCallText(calleeText)) {
      return;
    }

    if (!networkCallUsesAbortSignal(candidate)) {
      unsafe.push(candidate);
    }
  });

  return unsafe;
}

function effectAppearsToHydrateStateFromNetwork(
  effectBody: TSESTree.Node,
  sourceText: string,
): boolean {
  let usesStatefulSetter = false;

  walkAst(effectBody, (candidate: TSESTree.Node) => {
    if (candidate.type !== 'CallExpression') {
      return;
    }

    if (
      candidate.callee.type === 'Identifier' &&
      /^set[A-Z]/u.test(candidate.callee.name)
    ) {
      usesStatefulSetter = true;
    }

    for (const argument of candidate.arguments) {
      if (
        argument.type === 'Identifier' &&
        /^set[A-Z]/u.test(argument.name)
      ) {
        usesStatefulSetter = true;
      }
    }
  });

  if (!usesStatefulSetter) {
    return false;
  }

  let issuesNetworkRequest = false;

  walkAst(effectBody, (candidate: TSESTree.Node) => {
    if (candidate.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(candidate.callee, sourceText);

    if (isFetchLikeCallText(calleeText)) {
      issuesNetworkRequest = true;
    }

    if (
      candidate.callee.type === 'MemberExpression' &&
      candidate.callee.property.type === 'Identifier' &&
      candidate.callee.property.name === 'then' &&
      candidate.callee.object.type === 'CallExpression'
    ) {
      const nestedCallee = getCalleeText(
        candidate.callee.object.callee,
        sourceText,
      );

      if (isFetchLikeCallText(nestedCallee)) {
        issuesNetworkRequest = true;
      }
    }
  });

  return issuesNetworkRequest;
}

function collectEffectFetchCancellationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (/\.(?:test|spec)\.[tj]sx?$/iu.test(context.path)) {
    return facts;
  }

  walkAst(context.program, (node: TSESTree.Node) => {
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

    const effectBody: TSESTree.Node =
      callback.body.type === 'BlockStatement' ? callback.body : callback.body;

    const bodyText = getNodeText(effectBody, context.sourceText) ?? '';

    if (effectUsesDataLoadingPrimitives(bodyText)) {
      return;
    }

    const unsafeFetches = collectUnsafeFetchCallsInEffectBody(
      effectBody,
      context.sourceText,
    );

    if (unsafeFetches.length === 0) {
      return;
    }

    if (!effectAppearsToHydrateStateFromNetwork(effectBody, context.sourceText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: 'performance.react-effect-fetch-without-cancellation',
        node: unsafeFetches[0],
        nodeIds: context.nodeIds,
        props: {
          effectHook: calleeText,
        },
        text: getNodeText(unsafeFetches[0], context.sourceText),
      }),
    );
  });

  return facts;
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
    ...collectEffectFetchCancellationFacts(context),
    ...collectNextBoundaryLeakFacts(context),
  ];
}

