import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, getCalleeText, walkAst, walkAstWithAncestors } from '../../ast';
import { createObservedFact, isFunctionLike, type TypeScriptFactDetectorContext } from '../shared';

const HOOK_PATTERN = /^use[A-Z]/;

function isHookCall(calleeText: string): boolean {
  return HOOK_PATTERN.test(calleeText);
}

function isComponentOrHook(
  node: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
): boolean {
  const name =
    node.type === 'FunctionDeclaration'
      ? node.id?.name
      : undefined;

  if (!name) return false;
  if (/^[A-Z]/.test(name)) return true;
  if (name.startsWith('use') && /^use[A-Z]/.test(name)) return true;
  return false;
}

function getEnclosingFunction(
  ancestors: readonly TSESTree.Node[],
): TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression | undefined {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (isFunctionLike(node)) {
      return node;
    }
  }
  return undefined;
}

function getEnclosingFunctionName(
  func: TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression,
): string | undefined {
  if (func.type === 'FunctionDeclaration') {
    return func.id?.name;
  }
  return undefined;
}

function isVariableNameComponentOrHook(
  node: TSESTree.CallExpression,
  ancestors: readonly TSESTree.Node[],
): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];

    if (ancestor.type === 'VariableDeclarator' && ancestor.id.type === 'Identifier') {
      const name = ancestor.id.name;
      if (/^[A-Z]/.test(name)) return true;
      if (name.startsWith('use') && /^use[A-Z]/.test(name)) return true;
      return false;
    }

    if (
      ancestor.type === 'AssignmentExpression' &&
      ancestor.left.type === 'Identifier'
    ) {
      const name = ancestor.left.name;
      if (/^[A-Z]/.test(name)) return true;
      if (name.startsWith('use') && /^use[A-Z]/.test(name)) return true;
      return false;
    }

    if (
      ancestor.type === 'Property' &&
      !ancestor.computed &&
      ancestor.key.type === 'Identifier'
    ) {
      if (ancestor.key.name === 'Component') {
        return true;
      }
      return false;
    }

    if (ancestor.type === 'ExportDefaultDeclaration') {
      return true;
    }

    if (
      ancestor.type === 'CallExpression' &&
      ancestor.callee.type === 'MemberExpression' &&
      !ancestor.callee.computed &&
      ancestor.callee.property.type === 'Identifier' &&
      (ancestor.callee.property.name === 'memo' || ancestor.callee.property.name === 'forwardRef')
    ) {
      return true;
    }
  }

  return false;
}

function isInsideConditionalBlock(
  ancestors: readonly TSESTree.Node[],
  hookNode: TSESTree.Node,
): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];

    if (isFunctionLike(ancestor) && ancestor !== hookNode) {
      break;
    }

    if (
      ancestor.type === 'IfStatement' ||
      ancestor.type === 'ConditionalExpression' ||
      ancestor.type === 'SwitchCase'
    ) {
      return true;
    }
  }

  return false;
}

function isInsideLoop(
  ancestors: readonly TSESTree.Node[],
  hookNode: TSESTree.Node,
): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];

    if (isFunctionLike(ancestor) && ancestor !== hookNode) {
      break;
    }

    if (
      ancestor.type === 'ForStatement' ||
      ancestor.type === 'WhileStatement' ||
      ancestor.type === 'DoWhileStatement' ||
      ancestor.type === 'ForInStatement' ||
      ancestor.type === 'ForOfStatement'
    ) {
      return true;
    }
  }

  return false;
}

export function collectRulesOfHooksFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== 'CallExpression') return;

    const calleeText = getCalleeText(node.callee, sourceText) ?? '';
    if (!isHookCall(calleeText)) return;

    const enclosingFn = getEnclosingFunction(ancestors);
    if (!enclosingFn) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'framework.react.hooks-rule-violation',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            violation: 'top-level',
            callee: calleeText,
          },
        }),
      );
      return;
    }

    const fnName = getEnclosingFunctionName(enclosingFn);
    const isFnComponentOrHook =
      (fnName && (/^[A-Z]/.test(fnName) || (fnName.startsWith('use') && /^use[A-Z]/.test(fnName)))) ||
      isVariableNameComponentOrHook(node, ancestors);

    if (!isFnComponentOrHook) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'framework.react.hooks-rule-violation',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            violation: 'non-component',
            callee: calleeText,
          },
        }),
      );
      return;
    }

    if (isInsideConditionalBlock(ancestors, node)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'framework.react.hooks-rule-violation',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            violation: 'conditional',
            callee: calleeText,
          },
        }),
      );
      return;
    }

    if (isInsideLoop(ancestors, node)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'framework.react.hooks-rule-violation',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            violation: 'loop',
            callee: calleeText,
          },
        }),
      );
      return;
    }
  });

  return facts;
}
