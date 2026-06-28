import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import {
  createObservedFact,
  isBooleanLiteral,
  type TypeScriptFactDetector,
} from './shared';

const ARRAY_METHODS_EXPECTING_SYNC_CALLBACK = new Set([
  'every',
  'filter',
  'find',
  'findIndex',
  'forEach',
  'map',
  'reduce',
  'reduceRight',
  'some',
  'sort',
]);

const PROMISE_LIKE_CALLEE_PATTERN =
  /^(?:fetch|axios(?:\.[a-z]+)?|prisma\.|db\.|repository\.|Promise\.)/;

const SYNC_AWAIT_CALLEE_PATTERN =
  /^(?:Math\.|JSON\.(?:parse|stringify)|parseInt|parseFloat|Number\.|String\.|Object\.(?:keys|values|entries|assign|freeze)|Array\.from)/;

function collectAsyncFunctionNames(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();

  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.async && node.id) {
      names.add(node.id.name);
    }

    if (node.type === 'VariableDeclarator' && node.id.type === 'Identifier' && node.init) {
      const init = node.init;
      if (
        (init.type === 'ArrowFunctionExpression' || init.type === 'FunctionExpression') &&
        init.async
      ) {
        names.add(node.id.name);
      }
    }
  });

  return names;
}

function isLoopNode(node: TSESTree.Node): boolean {
  return (
    node.type === 'ForStatement' ||
    node.type === 'ForInStatement' ||
    node.type === 'ForOfStatement' ||
    node.type === 'WhileStatement' ||
    node.type === 'DoWhileStatement'
  );
}

function loopBodyHasExit(body: TSESTree.Statement): boolean {
  let found = false;

  walkAst(body, (inner) => {
    if (found) {
      return;
    }

    if (
      inner.type === 'BreakStatement' ||
      inner.type === 'ReturnStatement' ||
      inner.type === 'ThrowStatement'
    ) {
      found = true;
      return;
    }

    if (inner.type === 'YieldExpression') {
      found = true;
      return;
    }

    if (
      inner.type === 'CallExpression' &&
      inner.callee.type === 'MemberExpression' &&
      inner.callee.object.type === 'Identifier' &&
      inner.callee.object.name === 'process' &&
      inner.callee.property.type === 'Identifier' &&
      (inner.callee.property.name === 'exit' || inner.callee.property.name === 'abort')
    ) {
      found = true;
    }
  });

  return found;
}

function calleeText(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): string | undefined {
  return getNodeText(callExpression.callee, sourceText) ?? undefined;
}

function looksPromiseReturningCall(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
  asyncFunctionNames: ReadonlySet<string>,
): boolean {
  const text = calleeText(callExpression, sourceText);

  if (!text) {
    return false;
  }

  if (asyncFunctionNames.has(text)) {
    return true;
  }

  if (PROMISE_LIKE_CALLEE_PATTERN.test(text)) {
    return true;
  }

  return /Async$/.test(text.split('.').at(-1) ?? text);
}

function isSyncAwaitArgument(argument: TSESTree.Expression): boolean {
  if (
    argument.type === 'Literal' ||
    argument.type === 'TemplateLiteral' ||
    argument.type === 'ArrayExpression' ||
    argument.type === 'ObjectExpression'
  ) {
    return true;
  }

  if (argument.type !== 'CallExpression') {
    return false;
  }

  const calleeTextValue =
    argument.callee.type === 'Identifier'
      ? argument.callee.name
      : argument.callee.type === 'MemberExpression' &&
          argument.callee.property.type === 'Identifier'
        ? `${argument.callee.object.type === 'Identifier' ? argument.callee.object.name : ''}.${argument.callee.property.name}`
        : undefined;

  return calleeTextValue ? SYNC_AWAIT_CALLEE_PATTERN.test(calleeTextValue) : false;
}

function callbackUsesAwaitWithoutAsync(
  callback:
    | TSESTree.ArrowFunctionExpression
    | TSESTree.FunctionExpression,
): boolean {
  if (callback.async) {
    return false;
  }

  let usesAwait = false;
  walkAst(callback.body, (inner) => {
    if (inner.type === 'AwaitExpression') {
      usesAwait = true;
    }
  });

  return usesAwait;
}

function isPromiseHandlerCall(
  callExpression: TSESTree.CallExpression,
): boolean {
  if (callExpression.callee.type !== 'MemberExpression') {
    return false;
  }

  if (callExpression.callee.property.type !== 'Identifier') {
    return false;
  }

  return ['then', 'catch', 'finally'].includes(callExpression.callee.property.name);
}

function hasTryAncestor(ancestors: readonly TSESTree.Node[]): boolean {
  return ancestors.some((ancestor) => ancestor.type === 'TryStatement');
}

function hasAsyncFunctionAncestor(ancestors: readonly TSESTree.Node[]): boolean {
  return ancestors.some(
    (ancestor) =>
      (ancestor.type === 'FunctionDeclaration' ||
        ancestor.type === 'FunctionExpression' ||
        ancestor.type === 'ArrowFunctionExpression') &&
      ancestor.async,
  );
}

function isVoidExpressionStatement(statement: TSESTree.ExpressionStatement): boolean {
  return (
    statement.expression.type === 'UnaryExpression' &&
    statement.expression.operator === 'void'
  );
}

function isWrappedByPromiseConstructor(
  ancestors: readonly TSESTree.Node[],
): boolean {
  if (ancestors.length === 0) {
    return false;
  }

  const parent = ancestors[ancestors.length - 1];

  if (parent.type !== 'CallExpression') {
    return false;
  }

  const callee = parent.callee;

  if (callee.type !== 'MemberExpression') {
    return false;
  }

  return (
    callee.object.type === 'Identifier' &&
    callee.object.name === 'Promise' &&
    callee.property.type === 'Identifier' &&
    (callee.property.name === 'all' || callee.property.name === 'allSettled')
  );
}

/**
 * Collects async correctness facts: infinite loops, await misuse, floating promises.
 */
export const collectTypescriptAsyncCorrectnessFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;
  const asyncFunctionNames = collectAsyncFunctionNames(program);

  walkAst(program, (node) => {
    if (node.type === 'WhileStatement' && isBooleanLiteral(node.test, true)) {
      if (!loopBodyHasExit(node.body)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'async.infinite-loop',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
      return;
    }

    if (node.type === 'DoWhileStatement' && isBooleanLiteral(node.test, true)) {
      if (!loopBodyHasExit(node.body)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'async.infinite-loop',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
      return;
    }

    if (node.type === 'ForStatement' && node.test == null) {
      if (!loopBodyHasExit(node.body)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'async.infinite-loop',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }
  });

  walkAstWithAncestors(program, (node, ancestors) => {
    if (
      node.type === 'ReturnStatement' &&
      node.argument?.type === 'AwaitExpression' &&
      hasAsyncFunctionAncestor(ancestors) &&
      !hasTryAncestor(ancestors)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'async.unnecessary-return-await',
          node: node.argument,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
    }

    if (node.type === 'AwaitExpression' && isSyncAwaitArgument(node.argument)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'async.invalid-await-expression',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
    }

    if (node.type === 'CallExpression' && isPromiseHandlerCall(node)) {
      const callback = node.arguments[0];
      if (
        callback &&
        callback.type !== 'SpreadElement' &&
        (callback.type === 'ArrowFunctionExpression' ||
          callback.type === 'FunctionExpression') &&
        callbackUsesAwaitWithoutAsync(callback)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'async.missing-async-on-promise-method',
            node: callback,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.property.type === 'Identifier' &&
      ARRAY_METHODS_EXPECTING_SYNC_CALLBACK.has(node.callee.property.name)
    ) {
      const callback = node.arguments[0];
      if (
        callback &&
        callback.type !== 'SpreadElement' &&
        (callback.type === 'ArrowFunctionExpression' ||
          callback.type === 'FunctionExpression') &&
        callback.async
      ) {
        if (!isWrappedByPromiseConstructor(ancestors)) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: 'async.misused-promises',
              node: callback,
              nodeIds,
              text: getNodeText(node, sourceText),
            }),
          );
        }
      }
    }

    if (
      node.type === 'ExpressionStatement' &&
      !isVoidExpressionStatement(node) &&
      node.expression.type === 'CallExpression' &&
      !isPromiseHandlerCall(node.expression) &&
      looksPromiseReturningCall(node.expression, sourceText, asyncFunctionNames)
    ) {
      const inAsyncFunction = hasAsyncFunctionAncestor(ancestors);
      const callee = calleeText(node.expression, sourceText);

      if (inAsyncFunction && callee && asyncFunctionNames.has(callee)) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'async.floating-promise-in-function',
          node: node.expression,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
    }
  });

  return facts;
};
