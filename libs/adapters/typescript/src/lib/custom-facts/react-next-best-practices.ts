import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  isNode,
  walkAst,
  walkAstWithAncestors,
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

      const contextProp = getObjectProperty(argument, 'context');

      if (contextProp?.value.type === 'ObjectExpression') {
        const fetchOptions = getObjectProperty(
          contextProp.value,
          'fetchOptions',
        );

        if (
          fetchOptions?.value.type === 'ObjectExpression' &&
          getObjectProperty(fetchOptions.value, 'signal')
        ) {
          return true;
        }
      }
    }
  }

  return false;
}

function objectTextMatchesGraphQlClientHint(objectText: string): boolean {
  const lower = objectText.toLowerCase();

  return (
    lower.includes('apollo') ||
    lower.includes('graphql') ||
    lower.includes('relay') ||
    /\bclient\b/u.test(objectText) ||
    /\bgql\b/u.test(lower)
  );
}

function isLikelyGraphQlClientCall(
  call: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  if (call.callee.type !== 'MemberExpression') {
    return false;
  }

  if (call.callee.property.type !== 'Identifier') {
    return false;
  }

  const method = call.callee.property.name;

  if (method !== 'query' && method !== 'mutate') {
    return false;
  }

  const objectText = getNodeText(call.callee.object, sourceText) ?? '';

  return objectTextMatchesGraphQlClientHint(objectText);
}

function collectGraphqlRequestCalleeNames(
  program: TSESTree.Program,
): Set<string> {
  const names = new Set<string>();

  walkAst(program, (node: TSESTree.Node) => {
    if (node.type !== 'ImportDeclaration') {
      return;
    }

    if (node.source.value !== 'graphql-request') {
      return;
    }

    for (const specifier of node.specifiers) {
      if (specifier.type === 'ImportDefaultSpecifier') {
        names.add(specifier.local.name);
      }

      if (specifier.type === 'ImportSpecifier') {
        const imported =
          specifier.imported.type === 'Identifier'
            ? specifier.imported.name
            : specifier.imported.value;

        if (imported === 'request') {
          names.add(specifier.local.name);
        }
      }
    }
  });

  return names;
}

function effectCallbackUsesStaleResponseGuard(
  callback:
    | TSESTree.ArrowFunctionExpression
    | TSESTree.FunctionExpression,
): boolean {
  if (callback.body.type !== 'BlockStatement') {
    return false;
  }

  const block = callback.body;
  const falseInitFlags = new Map<string, string>();
  const trueInitFlags = new Map<string, string>();

  for (const statement of block.body) {
    if (statement.type !== 'VariableDeclaration' || statement.kind !== 'let') {
      continue;
    }

    for (const declarator of statement.declarations) {
      if (declarator.id.type !== 'Identifier' || !declarator.init) {
        continue;
      }

      const name = declarator.id.name;

      if (
        declarator.init.type === 'Literal' &&
        declarator.init.value === false
      ) {
        falseInitFlags.set(name, name);
      }

      if (
        declarator.init.type === 'Literal' &&
        declarator.init.value === true
      ) {
        trueInitFlags.set(name, name);
      }
    }
  }

  let cleanupBody: TSESTree.BlockStatement | undefined;

  for (const statement of block.body) {
    if (statement.type !== 'ReturnStatement' || !statement.argument) {
      continue;
    }

    const argument = statement.argument;

    if (argument.type === 'ArrowFunctionExpression') {
      if (argument.body.type === 'BlockStatement') {
        cleanupBody = argument.body;
      }

      continue;
    }

    if (argument.type === 'FunctionExpression') {
      cleanupBody = argument.body;
    }
  }

  if (!cleanupBody) {
    return false;
  }

  const toggledFalseInit = new Set<string>();
  const toggledTrueInit = new Set<string>();

  walkAst(cleanupBody, (node: TSESTree.Node) => {
    if (node.type !== 'AssignmentExpression' || node.operator !== '=') {
      return;
    }

    if (node.left.type !== 'Identifier') {
      return;
    }

    if (node.right.type !== 'Literal') {
      return;
    }

    const leftName = node.left.name;

    if (falseInitFlags.has(leftName) && node.right.value === true) {
      toggledFalseInit.add(leftName);
    }

    if (trueInitFlags.has(leftName) && node.right.value === false) {
      toggledTrueInit.add(leftName);
    }
  });

  const guardedFalseInit = [...toggledFalseInit].some((flagName) =>
    blockUsesConditionalBeforeStatefulSetter(block, flagName, 'negated'),
  );
  const guardedTrueInit = [...toggledTrueInit].some((flagName) =>
    blockUsesConditionalBeforeStatefulSetter(block, flagName, 'truthy'),
  );

  return guardedFalseInit || guardedTrueInit;
}

function blockUsesConditionalBeforeStatefulSetter(
  block: TSESTree.BlockStatement,
  flagName: string,
  mode: 'negated' | 'truthy',
): boolean {
  let found = false;

  walkAst(block, (node: TSESTree.Node) => {
    if (found) {
      return;
    }

    if (node.type !== 'IfStatement') {
      return;
    }

    if (!ifStatementTestsFlag(node.test, flagName, mode)) {
      return;
    }

    const thenBranch = node.consequent;

    if (containsStatefulSetterCall(thenBranch)) {
      found = true;
    }
  });

  return found;
}

function ifStatementTestsFlag(
  test: TSESTree.Expression,
  flagName: string,
  mode: 'negated' | 'truthy',
): boolean {
  if (mode === 'negated') {
    if (test.type === 'UnaryExpression' && test.operator === '!') {
      return expressionReferencesIdentifier(test.argument, flagName);
    }

    return false;
  }

  return expressionReferencesIdentifier(test, flagName);
}

function expressionReferencesIdentifier(
  expression: TSESTree.Expression,
  identifier: string,
): boolean {
  if (expression.type === 'Identifier') {
    return expression.name === identifier;
  }

  if (expression.type === 'MemberExpression') {
    return (
      expression.property.type === 'Identifier' &&
      expression.property.name === identifier &&
      expression.object.type === 'ThisExpression'
    );
  }

  return false;
}

function containsStatefulSetterCall(node: TSESTree.Node): boolean {
  let found = false;

  walkAst(node, (candidate: TSESTree.Node) => {
    if (found) {
      return;
    }

    if (candidate.type !== 'CallExpression') {
      return;
    }

    if (
      candidate.callee.type === 'Identifier' &&
      /^set[A-Z]/u.test(candidate.callee.name)
    ) {
      found = true;
    }
  });

  return found;
}

function innermostEnclosingFunctionLike(
  ancestors: readonly TSESTree.Node[],
):
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionExpression
  | TSESTree.FunctionDeclaration
  | undefined {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const candidate = ancestors[index];

    if (
      candidate.type === 'FunctionDeclaration' ||
      candidate.type === 'FunctionExpression' ||
      candidate.type === 'ArrowFunctionExpression'
    ) {
      return candidate;
    }
  }

  return undefined;
}

function enclosingFunctionUsesRouteLoaderData(
  ancestors: readonly TSESTree.Node[],
  sourceText: string,
): boolean {
  const enclosing = innermostEnclosingFunctionLike(ancestors);

  if (!enclosing || enclosing.body.type !== 'BlockStatement') {
    return false;
  }

  return /\buse(?:Loader|RouteLoader)Data\b/u.test(
    getNodeText(enclosing.body, sourceText) ?? '',
  );
}

function isEffectNetworkCall(
  call: TSESTree.CallExpression,
  sourceText: string,
  graphqlRequestCalleeNames: Set<string>,
): boolean {
  const calleeText = getCalleeText(call.callee, sourceText);

  if (isFetchLikeCallText(calleeText)) {
    return true;
  }

  if (isLikelyGraphQlClientCall(call, sourceText)) {
    return true;
  }

  if (
    call.callee.type === 'Identifier' &&
    graphqlRequestCalleeNames.has(call.callee.name)
  ) {
    return true;
  }

  return false;
}

function collectUnsafeFetchCallsInEffectBody(
  effectBody: TSESTree.Node,
  sourceText: string,
  graphqlRequestCalleeNames: Set<string>,
): TSESTree.CallExpression[] {
  const unsafe: TSESTree.CallExpression[] = [];

  walkAst(effectBody, (candidate: TSESTree.Node) => {
    if (candidate.type !== 'CallExpression') {
      return;
    }

    if (!isEffectNetworkCall(candidate, sourceText, graphqlRequestCalleeNames)) {
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
  graphqlRequestCalleeNames: Set<string>,
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

    if (isEffectNetworkCall(candidate, sourceText, graphqlRequestCalleeNames)) {
      issuesNetworkRequest = true;
    }

    if (
      candidate.callee.type === 'MemberExpression' &&
      candidate.callee.property.type === 'Identifier' &&
      candidate.callee.property.name === 'then' &&
      candidate.callee.object.type === 'CallExpression'
    ) {
      const innerCall = candidate.callee.object;

      if (isEffectNetworkCall(innerCall, sourceText, graphqlRequestCalleeNames)) {
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

  const graphqlRequestCalleeNames = collectGraphqlRequestCalleeNames(
    context.program,
  );

  walkAstWithAncestors(context.program, (node, ancestors) => {
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

    if (enclosingFunctionUsesRouteLoaderData(ancestors, context.sourceText)) {
      return;
    }

    if (effectCallbackUsesStaleResponseGuard(callback)) {
      return;
    }

    const unsafeFetches = collectUnsafeFetchCallsInEffectBody(
      effectBody,
      context.sourceText,
      graphqlRequestCalleeNames,
    );

    if (unsafeFetches.length === 0) {
      return;
    }

    if (
      !effectAppearsToHydrateStateFromNetwork(
        effectBody,
        context.sourceText,
        graphqlRequestCalleeNames,
      )
    ) {
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

