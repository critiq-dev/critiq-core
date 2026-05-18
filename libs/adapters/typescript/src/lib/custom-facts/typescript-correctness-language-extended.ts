import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import { createObservedFact, type TypeScriptFactDetector } from './shared';

const VALID_TYPEOF_RESULTS = new Set([
  'undefined',
  'object',
  'boolean',
  'number',
  'bigint',
  'string',
  'symbol',
  'function',
]);

const ARRAY_CALLBACK_METHODS = new Set(['map', 'filter', 'reduce', 'every', 'some']);

const ARRAY_LIKE_IDENTIFIER_PATTERN =
  /^(arr|array|items|list|values|data|nums|numbers|elements|results|rows|entries|collection)$/i;

const ARRAY_PRODUCING_METHODS = new Set([
  'map',
  'filter',
  'slice',
  'concat',
  'splice',
  'sort',
  'reverse',
  'flat',
  'flatMap',
  'fill',
  'toSorted',
  'toReversed',
]);

function normalizeComparisonText(text: string | undefined): string | undefined {
  return text?.replace(/\s+/g, ' ').trim();
}

function isNaNIdentifier(node: TSESTree.Expression): boolean {
  return node.type === 'Identifier' && node.name === 'NaN';
}

function isTypeofUnary(
  node: TSESTree.Expression,
): node is TSESTree.UnaryExpression {
  return node.type === 'UnaryExpression' && node.operator === 'typeof';
}

function isFunctionLike(
  node: TSESTree.Node,
): node is
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | TSESTree.ArrowFunctionExpression {
  return (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

function isSuperCall(node: TSESTree.Node): boolean {
  return node.type === 'CallExpression' && node.callee.type === 'Super';
}

function isNonErrorLiteralExpression(node: TSESTree.Expression): boolean {
  if (node.type === 'Literal') {
    return true;
  }

  return node.type === 'TemplateLiteral';
}

function callbackHasReturnInBody(
  fn:
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
): boolean {
  if (fn.body.type !== 'BlockStatement') {
    return true;
  }

  let hasReturn = false;

  walkAstWithAncestors(fn.body, (node, ancestors) => {
    if (hasReturn || node.type !== 'ReturnStatement') {
      return;
    }

    let containingFunction: TSESTree.Node | undefined;

    for (let index = ancestors.length - 1; index >= 0; index -= 1) {
      const ancestor = ancestors[index];
      if (ancestor && isFunctionLike(ancestor)) {
        containingFunction = ancestor;
        break;
      }
    }

    if (containingFunction === fn) {
      hasReturn = true;
    }
  });

  return hasReturn;
}

function isPromiseRejectCall(node: TSESTree.CallExpression): boolean {
  if (node.callee.type !== 'MemberExpression') {
    return false;
  }

  if (
    node.callee.object.type !== 'Identifier' ||
    node.callee.object.name !== 'Promise'
  ) {
    return false;
  }

  return (
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'reject'
  );
}

function isExecutorRejectCall(
  node: TSESTree.CallExpression,
  ancestors: readonly TSESTree.Node[],
): boolean {
  if (node.callee.type !== 'Identifier' || node.callee.name !== 'reject') {
    return false;
  }

  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];

    if (
      ancestor.type === 'NewExpression' &&
      ancestor.callee.type === 'Identifier' &&
      ancestor.callee.name === 'Promise' &&
      ancestor.arguments.length > 0
    ) {
      const executor = ancestor.arguments[0];
      return (
        executor !== undefined &&
        executor.type !== 'SpreadElement' &&
        isFunctionLike(executor)
      );
    }
  }

  return false;
}

function isAsyncFunctionAncestor(
  ancestors: readonly TSESTree.Node[],
): boolean {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];

    if (
      (ancestor.type === 'FunctionDeclaration' ||
        ancestor.type === 'FunctionExpression' ||
        ancestor.type === 'ArrowFunctionExpression') &&
      ancestor.async
    ) {
      return true;
    }
  }

  return false;
}

function looksLikeArrayExpression(
  expression: TSESTree.Expression,
): boolean {
  if (expression.type === 'ArrayExpression') {
    return true;
  }

  if (expression.type === 'Identifier') {
    return ARRAY_LIKE_IDENTIFIER_PATTERN.test(expression.name);
  }

  if (expression.type === 'MemberExpression') {
    if (expression.property.type === 'Identifier') {
      if (expression.property.name === 'length') {
        return true;
      }

      if (ARRAY_PRODUCING_METHODS.has(expression.property.name)) {
        return true;
      }
    }

    return looksLikeArrayExpression(expression.object as TSESTree.Expression);
  }

  if (expression.type === 'CallExpression') {
    if (
      expression.callee.type === 'Identifier' &&
      expression.callee.name === 'Array'
    ) {
      return true;
    }

    if (expression.callee.type === 'MemberExpression') {
      if (
        expression.callee.property.type === 'Identifier' &&
        ARRAY_PRODUCING_METHODS.has(expression.callee.property.name)
      ) {
        return true;
      }
    }
  }

  if (expression.type === 'NewExpression') {
    return (
      expression.callee.type === 'Identifier' &&
      expression.callee.name === 'Array'
    );
  }

  return false;
}

function collectDuplicateIfElseChainFacts(
  head: TSESTree.IfStatement,
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seen = new Map<string, TSESTree.IfStatement>();
  let current: TSESTree.IfStatement | undefined = head;

  while (current) {
    const testText = normalizeComparisonText(getNodeText(current.test, sourceText));

    if (testText) {
      const prior = seen.get(testText);
      if (prior) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.duplicate-if-else-condition',
            node: current.test,
            nodeIds,
            text: getNodeText(current.test, sourceText),
            props: {
              test: testText,
            },
          }),
        );
      } else {
        seen.set(testText, current);
      }
    }

    if (current.alternate?.type === 'IfStatement') {
      current = current.alternate;
    } else {
      break;
    }
  }

  return facts;
}

function collectConstructorSuperFacts(
  classNode: TSESTree.ClassDeclaration | TSESTree.ClassExpression,
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): ObservedFact[] {
  if (!classNode.superClass) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const constructor = classNode.body.body.find(
    (member): member is TSESTree.MethodDefinition =>
      member.type === 'MethodDefinition' && member.kind === 'constructor',
  );

  if (!constructor) {
    return facts;
  }

  const body = constructor.value.body;
  if (!body || body.type !== 'BlockStatement') {
    return facts;
  }

  let hasSuperCall = false;
  let superCallStatementIndex = -1;

  for (let index = 0; index < body.body.length; index += 1) {
    const statement = body.body[index];
    let statementHasSuperCall = false;

    walkAst(statement, (node) => {
      if (statementHasSuperCall) {
        return;
      }

      if (isSuperCall(node)) {
        statementHasSuperCall = true;
      }
    });

    if (statementHasSuperCall) {
      hasSuperCall = true;
      superCallStatementIndex = index;
      break;
    }
  }

  if (!hasSuperCall) {
    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'language.missing-super-call',
        node: constructor,
        nodeIds,
        text: getNodeText(constructor, sourceText),
        props: {},
      }),
    );

    return facts;
  }

  for (let index = 0; index < superCallStatementIndex; index += 1) {
    const statement = body.body[index];

    walkAstWithAncestors(statement, (inner, ancestors) => {
      const parent = ancestors[ancestors.length - 1];

      if (inner.type === 'ThisExpression') {
        if (
          parent?.type === 'MemberExpression' &&
          parent.object === inner
        ) {
          return;
        }

        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.this-before-super',
            node: inner,
            nodeIds,
            text: getNodeText(inner, sourceText),
            props: {
              reason: 'this',
            },
          }),
        );
        return;
      }

      if (
        inner.type === 'MemberExpression' &&
        inner.object.type === 'ThisExpression'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.this-before-super',
            node: inner,
            nodeIds,
            text: getNodeText(inner, sourceText),
            props: {
              reason: 'this-member',
            },
          }),
        );
        return;
      }

      if (
        inner.type === 'MemberExpression' &&
        inner.object.type === 'Super'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.this-before-super',
            node: inner,
            nodeIds,
            text: getNodeText(inner, sourceText),
            props: {
              reason: 'super-member',
            },
          }),
        );
        return;
      }

      if (
        inner.type === 'CallExpression' &&
        inner.callee.type === 'MemberExpression' &&
        inner.callee.object.type === 'Super'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.this-before-super',
            node: inner,
            nodeIds,
            text: getNodeText(inner, sourceText),
            props: {
              reason: 'super-call',
            },
          }),
        );
      }
    });
  }

  return facts;
}

/**
 * Collects additional TypeScript/JavaScript language correctness facts
 * for control flow, comparisons, class constructors, and array idioms.
 */
export const collectTypescriptCorrectnessLanguageExtendedFacts: TypeScriptFactDetector =
  (context): ObservedFact[] => {
    const { program, sourceText, nodeIds } = context;
    const facts: ObservedFact[] = [];

    walkAst(program, (node) => {
      if (node.type === 'TryStatement' && node.finalizer) {
        walkAst(node.finalizer, (inner) => {
          if (
            inner.type !== 'ReturnStatement' &&
            inner.type !== 'ThrowStatement' &&
            inner.type !== 'BreakStatement' &&
            inner.type !== 'ContinueStatement'
          ) {
            return;
          }

          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.control-flow-in-finally',
              node: inner,
              nodeIds,
              text: getNodeText(inner, sourceText),
              props: {
                statement: inner.type,
              },
            }),
          );
        });
      }

      if (
        node.type === 'BinaryExpression' &&
        ['===', '==', '!==', '!='].includes(node.operator)
      ) {
        const leftOperand =
          node.left.type === 'PrivateIdentifier' ? undefined : node.left;
        const rightOperand = node.right;

        if (
          (leftOperand && isNaNIdentifier(leftOperand)) ||
          (rightOperand && isNaNIdentifier(rightOperand))
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.use-number-is-nan',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                operator: node.operator,
              },
            }),
          );
        }

        let typeofSide: TSESTree.UnaryExpression | undefined;
        let comparisonSide: TSESTree.Expression | undefined;

        if (leftOperand && isTypeofUnary(leftOperand)) {
          typeofSide = leftOperand;
          comparisonSide = rightOperand;
        } else if (rightOperand && isTypeofUnary(rightOperand)) {
          typeofSide = rightOperand;
          comparisonSide = leftOperand;
        }

        if (
          typeofSide &&
          comparisonSide?.type === 'Literal' &&
          typeof comparisonSide.value === 'string' &&
          !VALID_TYPEOF_RESULTS.has(comparisonSide.value)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.invalid-typeof-comparison',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                typeofResult: comparisonSide.value,
              },
            }),
          );
        }
      }

      if (
        node.type === 'CallExpression' &&
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        ARRAY_CALLBACK_METHODS.has(node.callee.property.name)
      ) {
        const callback = node.arguments[0];
        if (
          callback &&
          callback.type !== 'SpreadElement' &&
          (callback.type === 'FunctionExpression' ||
            callback.type === 'ArrowFunctionExpression') &&
          !callbackHasReturnInBody(callback)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.array-callback-missing-return',
              node: callback,
              nodeIds,
              text: getNodeText(callback, sourceText),
              props: {
                method: node.callee.property.name,
              },
            }),
          );
        }
      }

      if (
        node.type === 'CallExpression' &&
        node.callee.type === 'MemberExpression' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'sort' &&
        node.arguments.length === 0
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.array-sort-without-compare',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (node.type === 'ForInStatement' && looksLikeArrayExpression(node.right)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.for-in-on-array',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (
        (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') &&
        node.superClass
      ) {
        facts.push(...collectConstructorSuperFacts(node, nodeIds, sourceText));
      }
    });

    walkAstWithAncestors(program, (node, ancestors) => {
      if (node.type === 'IfStatement') {
        const parent = ancestors[ancestors.length - 1];
        if (parent?.type === 'IfStatement' && parent.alternate === node) {
          return;
        }

        facts.push(
          ...collectDuplicateIfElseChainFacts(node, nodeIds, sourceText),
        );
      }

      if (node.type === 'CallExpression') {
        const argument = node.arguments[0];

        if (
          isPromiseRejectCall(node) &&
          argument &&
          argument.type !== 'SpreadElement' &&
          isNonErrorLiteralExpression(argument)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.promise-reject-non-error',
              node: argument,
              nodeIds,
              text: getNodeText(argument, sourceText),
              props: {
                context: 'Promise.reject',
              },
            }),
          );
        }

        if (
          isExecutorRejectCall(node, ancestors) &&
          argument &&
          argument.type !== 'SpreadElement' &&
          isNonErrorLiteralExpression(argument)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.promise-reject-non-error',
              node: argument,
              nodeIds,
              text: getNodeText(argument, sourceText),
              props: {
                context: 'executor-reject',
              },
            }),
          );
        }
      }

      if (
        node.type === 'ThrowStatement' &&
        node.argument &&
        isNonErrorLiteralExpression(node.argument) &&
        isAsyncFunctionAncestor(ancestors)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.promise-reject-non-error',
            node: node.argument,
            nodeIds,
            text: getNodeText(node.argument, sourceText),
            props: {
              context: 'async-throw',
            },
          }),
        );
      }
    });

    return facts;
  };
