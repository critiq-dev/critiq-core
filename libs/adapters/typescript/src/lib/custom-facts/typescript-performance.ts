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
const TEST_FILE_PATTERNS = /[/\\](?:__?tests?__?|spec|test|tests|e2e-?tests?|integration-?tests?)[/\\]|\.(?:test|spec)\./i;
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

function isSleepAwait(node: TSESTree.AwaitExpression): boolean {
  const arg = node.argument;

  // Pattern: await new Promise(resolve => setTimeout(resolve, ...))
  if (
    arg.type === 'NewExpression' &&
    arg.callee.type === 'Identifier' &&
    arg.callee.name === 'Promise'
  ) {
    const callback = arg.arguments[0];
    if (
      callback &&
      (callback.type === 'ArrowFunctionExpression' || callback.type === 'FunctionExpression')
    ) {
      const resolveParam = callback.params[0];
      const resolveName =
        resolveParam?.type === 'Identifier' ? resolveParam.name : '';
      if (resolveName) {
        const body = callback.body;

        // Expression body: (resolve) => setTimeout(resolve, ...)
        if (
          body.type === 'CallExpression' &&
          body.callee.type === 'Identifier' &&
          body.callee.name === 'setTimeout'
        ) {
          const firstArg = body.arguments[0];
          if (firstArg?.type === 'Identifier' && firstArg.name === resolveName) {
            return true;
          }
        }

        // Block body: (resolve) => { setTimeout(resolve, ...); }
        if (body.type === 'BlockStatement') {
          for (const stmt of body.body) {
            if (
              stmt.type === 'ExpressionStatement' &&
              stmt.expression.type === 'CallExpression'
            ) {
              const call = stmt.expression;
              if (call.callee.type === 'Identifier' && call.callee.name === 'setTimeout') {
                const firstArg = call.arguments[0];
                if (firstArg?.type === 'Identifier' && firstArg.name === resolveName) {
                  return true;
                }
              }
            }
          }
        }
      }
    }
  }

  // Pattern: await delay(...) / await sleep(...) — promisified timer utilities
  if (arg.type === 'CallExpression') {
    const callee = arg.callee;
    if (callee.type === 'Identifier' && /^(?:delay|sleep|setTimeout)$/i.test(callee.name)) {
      return true;
    }
    if (
      callee.type === 'MemberExpression' &&
      callee.property.type === 'Identifier' &&
      /^(?:delay|sleep|setTimeout)$/i.test(callee.property.name)
    ) {
      return true;
    }
  }

  return false;
}

function isPromiseAllAwait(node: TSESTree.AwaitExpression): boolean {
  const arg = node.argument;
  if (arg.type !== 'CallExpression') return false;
  const callee = arg.callee;
  if (callee.type !== 'MemberExpression') return false;
  if (callee.object.type !== 'Identifier' || callee.object.name !== 'Promise') return false;
  if (callee.property.type !== 'Identifier') return false;
  return callee.property.name === 'all' || callee.property.name === 'allSettled';
}

function isStreamReadAwait(node: TSESTree.AwaitExpression): boolean {
  const arg = node.argument;
  if (arg.type !== 'CallExpression') return false;
  const callee = arg.callee;
  if (callee.type !== 'MemberExpression') return false;
  if (callee.property.type !== 'Identifier') return false;
  if (callee.property.name !== 'read') return false;
  const obj = callee.object;
  return obj.type === 'Identifier' && /(?:reader|stream)/i.test(obj.name);
}

function isTransactionalAwait(node: TSESTree.AwaitExpression): boolean {
  const arg = node.argument;
  if (arg.type !== 'CallExpression') return false;
  const callee = arg.callee;
  if (callee.type !== 'MemberExpression') return false;
  if (callee.property.type !== 'Identifier') return false;
  let obj = callee.object;
  while (obj.type === 'MemberExpression') {
    obj = obj.object;
  }
  return obj.type === 'Identifier' && obj.name === 'tx';
}

function isInsidePromiseCollectingCallback(
  ancestors: readonly TSESTree.Node[],
): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];
    if (
      (ancestor.type === 'ArrowFunctionExpression' || ancestor.type === 'FunctionExpression') &&
      (ancestor as { async?: boolean }).async
    ) {
      const parent = ancestors[i - 1];
      if (
        parent?.type === 'CallExpression' &&
        parent.callee.type === 'MemberExpression' &&
        parent.callee.property.type === 'Identifier' &&
        parent.callee.property.name === 'map'
      ) {
        for (let j = i - 2; j >= 0; j--) {
          const candidate = ancestors[j];
          if (
            candidate.type === 'CallExpression' &&
            candidate.callee.type === 'MemberExpression' &&
            candidate.callee.object.type === 'Identifier' &&
            candidate.callee.object.name === 'Promise' &&
            candidate.callee.property.type === 'Identifier' &&
            (candidate.callee.property.name === 'all' || candidate.callee.property.name === 'allSettled')
          ) {
            return true;
          }
        }
      }
      return false;
    }
    if (ancestor.type === 'FunctionDeclaration') {
      return false;
    }
  }
  return false;
}

function getFunctionSignatureText(
  node: TSESTree.Node,
  sourceText: string,
): string {
  if (
    node.type !== 'FunctionDeclaration' &&
    node.type !== 'FunctionExpression' &&
    node.type !== 'ArrowFunctionExpression'
  ) {
    return '';
  }
  const funcNode = node as
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression;
  if (!node.range || !funcNode.body?.range) {
    return '';
  }
  return sourceText.slice(node.range[0], funcNode.body.range[0]);
}

function looksLikeRequestHandler(node: TSESTree.Node, sourceText: string): boolean {
  if (
    node.type !== 'FunctionDeclaration' &&
    node.type !== 'FunctionExpression' &&
    node.type !== 'ArrowFunctionExpression'
  ) {
    return false;
  }
  const signature = getFunctionSignatureText(node, sourceText);
  return /\b(req|request|ctx|context|res|reply)\b/.test(signature);
}

export const collectTypescriptPerformanceFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { sourceText, program, nodeIds, path } = context;

  const seenObjectExpressions = new Set<string>();
  const seenArrayExpressions = new Set<string>();

  walkAstWithAncestors(program, (node, ancestors) => {
    const inLoop = hasLoopAncestor(node, ancestors);

    if (node.type === 'SpreadElement' && inLoop) {
      const parentNode = ancestors[ancestors.length - 1];
      if (parentNode?.type === 'ArrayExpression') {
        const key = `${parentNode.range[0]}-${parentNode.range[1]}`;
        if (!seenArrayExpressions.has(key)) {
          seenArrayExpressions.add(key);
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
      }
      if (parentNode?.type === 'ObjectExpression') {
        if (!isExcludedSourceFile(path, sourceText)) {
          const key = `${parentNode.range[0]}-${parentNode.range[1]}`;
          if (!seenObjectExpressions.has(key)) {
            seenObjectExpressions.add(key);
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
      if (isExcludedSourceFile(path, sourceText)) {
        return;
      }

      const firstArg = node.arguments[0];

      // Skip fixed-size array literals: Promise.all([a, b]) is bounded
      if (firstArg?.type === 'ArrayExpression') {
        return;
      }

      const argText = firstArg ? (getNodeText(firstArg, sourceText) ?? '') : '';

      // Flag Promise.all(collection.map(...)) — unbounded fan-out
      if (/\.map\s*\(/.test(argText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'performance.no-unbounded-concurrency',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
        return;
      }

      // Flag Promise.all(items) where the arg is a simple identifier named
      // like a collection — only at the top level to avoid false matches on
      // deeply nested sub-expressions inside ArrayExpression arguments.
      if (
        firstArg?.type === 'Identifier' &&
        /\b(items|rows|records|users|list)\b/i.test(firstArg.name)
      ) {
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
      if (isExcludedSourceFile(path, sourceText)) {
        return;
      }

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
      node.type === 'AwaitExpression' &&
      inLoop &&
      !isExcludedSourceFile(path, sourceText) &&
      !isSleepAwait(node) &&
      !isPromiseAllAwait(node) &&
      !isStreamReadAwait(node) &&
      !isTransactionalAwait(node) &&
      !isInsidePromiseCollectingCallback(ancestors)
    ) {
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
