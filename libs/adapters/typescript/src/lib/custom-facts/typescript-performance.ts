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

const BUNDLED_FILE_PATTERNS = /[./](?:bundle|bundled|min)[./-]/i;
const BUNDLED_MIN_NAMES = /\b(bundle|bundled|min)\b/i;
const TEST_FILE_PATTERNS = /[/\\](?:__?tests?__?|spec|test|tests)[/\\]|\.(?:test|spec)\./i;
const TUTORIAL_FILE_PATTERNS = /[/\\]tutorials?[/\\]|[/\\]examples?[/\\]/i;
const MINIFIED_LINE_THRESHOLD = 500;

function isSerializationContext(node: TSESTree.CallExpression, ancestors: readonly TSESTree.Node[]): boolean {
  const parent = ancestors[ancestors.length - 1];
  if (!parent || parent.type !== 'CallExpression') return false;
  const callee = parent.callee;
  if (callee.type === 'MemberExpression') {
    const prop = callee.property.type === 'Identifier' ? callee.property.name : '';
    const objText = callee.object.type === 'Identifier' ? callee.object.name : '';
    if ((objText === 'res' || objText === 'response' || objText === 'reply') && (prop === 'json' || prop === 'send')) return true;
    if (objText === 'fs' && (prop === 'writeFile' || prop === 'writeFileSync')) return true;
    if (prop === 'postMessage') return true;
  }
  if (callee.type === 'Identifier' && callee.name === 'postMessage') return true;
  return false;
}

function isExcludedSourceFile(path: string, sourceText: string): boolean {
  if (TEST_FILE_PATTERNS.test(path)) {
    return true;
  }
  if (TUTORIAL_FILE_PATTERNS.test(path)) {
    return true;
  }
  const fileName = path.split(/[/\\]/).pop() ?? '';
  if (BUNDLED_FILE_PATTERNS.test(fileName) || BUNDLED_MIN_NAMES.test(fileName)) {
    return true;
  }
  const firstLines = sourceText.split('\n', 5);
  if (firstLines.some((line) => line.length > MINIFIED_LINE_THRESHOLD)) {
    return true;
  }
  return false;
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
  const { sourceText, program, nodeIds, path } = context;

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
        if (!isExcludedSourceFile(path, sourceText) && !isSerializationContext(node, ancestors)) {
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

    if (node.type === 'AwaitExpression' && inLoop && !isExcludedSourceFile(path, sourceText)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'performance.no-await-in-loop',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );
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
