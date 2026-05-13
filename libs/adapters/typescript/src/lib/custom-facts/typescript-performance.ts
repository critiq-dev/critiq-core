import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAstWithAncestors } from '../ast';
import { createObservedFact, type TypeScriptFactDetector } from './shared';

function isLoopNode(node: TSESTree.Node): boolean {
  return (
    node.type === 'ForStatement' ||
    node.type === 'ForInStatement' ||
    node.type === 'ForOfStatement' ||
    node.type === 'WhileStatement' ||
    node.type === 'DoWhileStatement'
  );
}

function hasLoopAncestor(
  node: TSESTree.Node,
  parents: readonly TSESTree.Node[],
): boolean {
  if (isLoopNode(node)) {
    return true;
  }
  return parents.some((parent) => isLoopNode(parent));
}

function looksLikeRequestHandler(node: TSESTree.Node, sourceText: string): boolean {
  if (
    node.type !== 'FunctionDeclaration' &&
    node.type !== 'FunctionExpression' &&
    node.type !== 'ArrowFunctionExpression'
  ) {
    return false;
  }
  const signature = getNodeText(node, sourceText) ?? '';
  return /\b(req|request|ctx|context|res|reply)\b/.test(signature);
}

export const collectTypescriptPerformanceFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { sourceText, program, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    const inLoop = hasLoopAncestor(node, ancestors);

    if (node.type === 'SpreadElement' && inLoop) {
      const parentNode = ancestors[ancestors.length - 1];
      if (parentNode?.type === 'ArrayExpression') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-array-spread-in-hot-loop',
            node,
            nodeIds,
            text: getNodeText(parentNode, sourceText),
          }),
        );
      }
      if (parentNode?.type === 'ObjectExpression') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-large-object-spread-in-loop',
            node,
            nodeIds,
            text: getNodeText(parentNode, sourceText),
          }),
        );
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'concat' &&
      inLoop
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'performance.no-array-spread-in-hot-loop',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
    }

    if (
      node.type === 'NewExpression' &&
      node.callee.type === 'Identifier' &&
      node.callee.name === 'RegExp' &&
      inLoop
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'performance.no-regex-construction-in-loop',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'JSON' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'parse' &&
      node.arguments[0]?.type === 'CallExpression'
    ) {
      const inner = node.arguments[0];
      if (
        inner.callee.type === 'MemberExpression' &&
        inner.callee.object.type === 'Identifier' &&
        inner.callee.object.name === 'JSON' &&
        inner.callee.property.type === 'Identifier' &&
        inner.callee.property.name === 'stringify'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-json-parse-stringify-clone',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'Promise' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'all'
    ) {
      const argText = node.arguments[0]
        ? (getNodeText(node.arguments[0], sourceText) ?? '')
        : '';
      if (/\.map\s*\(/.test(argText) || /\b(items|rows|records|users|list)\b/i.test(argText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-unbounded-concurrency',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'fs' &&
      node.callee.property.type === 'Identifier' &&
      /Sync$/.test(node.callee.property.name)
    ) {
      const handler = ancestors.find((candidate) =>
        looksLikeRequestHandler(candidate, sourceText),
      );
      if (handler) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-sync-fs-in-request-path',
            node,
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
      (node.callee.property.name === 'sort' || node.callee.property.name === 'reduce')
    ) {
      const component = ancestors.find((candidate) => {
        if (candidate.type !== 'FunctionDeclaration' || !candidate.id?.name) {
          return false;
        }
        return /^[A-Z]/.test(candidate.id.name);
      });
      if (component) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-expensive-sort-in-render-path',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }
  });

  return facts;
};
