import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import { flatJsxElementsInFragment } from './jsx-elements';

const FACT_INDEX_KEY = 'ui.react.index-key-in-list';

function unwrapChainExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier,
): TSESTree.Expression | TSESTree.PrivateIdentifier {
  return node.type === 'ChainExpression'
    ? unwrapChainExpression(node.expression)
    : node;
}

function isMapCall(call: TSESTree.CallExpression): boolean {
  const callee = unwrapChainExpression(call.callee as TSESTree.Expression);

  return (
    callee.type === 'MemberExpression' &&
    !callee.computed &&
    callee.property.type === 'Identifier' &&
    callee.property.name === 'map'
  );
}

function collectCallbackParams(
  callback: TSESTree.CallExpressionArgument | undefined,
): { indexName: string | undefined } {
  if (
    callback &&
    callback.type !== 'SpreadElement' &&
    (callback.type === 'ArrowFunctionExpression' ||
      callback.type === 'FunctionExpression')
  ) {
    const indexParam = callback.params[1];

    if (indexParam?.type === 'Identifier') {
      return { indexName: indexParam.name };
    }
  }

  return { indexName: undefined };
}

function expressionUsesIdentifier(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier | undefined | null,
  name: string,
): boolean {
  if (!expr || expr.type === 'PrivateIdentifier') {
    return false;
  }

  let found = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (!found && node.type === 'Identifier' && node.name === name) {
      found = true;
    }
  });

  return found;
}

function jsxKeyUsesIndex(
  attr: TSESTree.JSXAttribute | TSESTree.JSXSpreadAttribute,
  indexName: string,
): boolean {
  if (
    attr.type !== 'JSXAttribute' ||
    attr.name.type !== 'JSXIdentifier' ||
    attr.name.name !== 'key' ||
    !attr.value ||
    attr.value.type !== 'JSXExpressionContainer'
  ) {
    return false;
  }

  const expr = attr.value.expression;

  if (expr.type === 'JSXEmptyExpression') {
    return false;
  }

  return expr.type === 'Identifier'
    ? expr.name === indexName
    : expressionUsesIdentifier(expr as TSESTree.Expression, indexName);
}

function unwrapExpression(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
): TSESTree.Expression | TSESTree.PrivateIdentifier {
  if (expr.type === 'TSAsExpression' || expr.type === 'TSTypeAssertion') {
    return unwrapExpression(expr.expression);
  }

  if ((expr as { type?: string }).type === 'ParenthesizedExpression') {
    return unwrapExpression(
      (expr as { expression: TSESTree.Expression }).expression,
    );
  }

  return expr;
}

function flagJsxRootsInExpression(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
  flagIssue: (jsx: TSESTree.JSXElement | TSESTree.JSXFragment) => void,
): void {
  const root = unwrapExpression(expr);

  if (root.type === 'JSXElement' || root.type === 'JSXFragment') {
    flagIssue(root);
    return;
  }

  walkAst(root as TSESTree.Node, (child) => {
    if (child.type === 'JSXElement' || child.type === 'JSXFragment') {
      flagIssue(child);
    }
  });
}

function callExpressionFromWalkNode(
  node: TSESTree.Node,
): TSESTree.CallExpression | undefined {
  if (node.type === 'CallExpression') {
    return node;
  }

  if (node.type === 'ChainExpression' && node.expression.type === 'CallExpression') {
    return node.expression;
  }

  return undefined;
}

/** Detects React list keys that use the map index. */
export function collectIndexKeyFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    const call = callExpressionFromWalkNode(node);

    if (!call || !isMapCall(call)) {
      return;
    }

    const { indexName } = collectCallbackParams(call.arguments[0]);

    if (!indexName) {
      return;
    }

    const flagIssue = (jsxOrFragment: TSESTree.JSXElement | TSESTree.JSXFragment) => {
      const elements =
        jsxOrFragment.type === 'JSXElement'
          ? [jsxOrFragment]
          : flatJsxElementsInFragment(jsxOrFragment);

      for (const jsx of elements) {
        for (const attr of jsx.openingElement.attributes) {
          if (!jsxKeyUsesIndex(attr, indexName)) {
            continue;
          }

          const issueNode =
            attr.type === 'JSXAttribute' &&
            attr.value?.type === 'JSXExpressionContainer'
              ? attr.value.expression
              : jsx.openingElement;

          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_INDEX_KEY,
              node: issueNode as TSESTree.Node,
              nodeIds: context.nodeIds,
              props: {
                indexParameter: indexName,
              },
              text: getNodeText(issueNode as TSESTree.Node, context.sourceText),
            }),
          );

          return;
        }
      }
    };

    const callback = call.arguments[0];

    if (
      callback &&
      callback.type !== 'SpreadElement' &&
      (callback.type === 'ArrowFunctionExpression' ||
        callback.type === 'FunctionExpression')
    ) {
      const body = callback.body;

      if (body.type === 'BlockStatement') {
        for (const statement of body.body) {
          if (statement.type === 'ReturnStatement' && statement.argument) {
            flagJsxRootsInExpression(statement.argument, flagIssue);
          }
        }
      } else {
        flagJsxRootsInExpression(body, flagIssue);
      }
    }
  });

  return dedupeFactsByRange(facts);
}
