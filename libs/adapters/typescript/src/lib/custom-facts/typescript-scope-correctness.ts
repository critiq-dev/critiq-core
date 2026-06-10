import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, isNode, walkAstWithAncestors } from '../ast';
import { createObservedFact, type TypeScriptFactDetector } from './shared';

const GLOBAL_IDENTIFIERS = new Set([
  'undefined',
  'NaN',
  'Infinity',
  'arguments',
  'eval',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite',
  'Object',
  'Array',
  'String',
  'Number',
  'Boolean',
  'Symbol',
  'BigInt',
  'Date',
  'RegExp',
  'Error',
  'Map',
  'Set',
  'Promise',
  'JSON',
  'Math',
  'console',
  'globalThis',
  'window',
  'document',
  'module',
  'exports',
  'require',
  'process',
  '__dirname',
  '__filename',
  'Buffer',
  'setTimeout',
  'setInterval',
  'clearTimeout',
  'clearInterval',
  'setImmediate',
  'queueMicrotask',
]);

const RESTRICTED_GLOBALS = new Set([
  'event',
  'name',
  'status',
  'parent',
  'self',
  'top',
  'frames',
  'opener',
  'closed',
  'length',
  'external',
]);

type Binding = {
  name: string;
  kind: 'var' | 'let' | 'const' | 'param' | 'import';
  declaredLine: number;
  referenced: boolean;
  node: TSESTree.Node;
};

function isTypeOrPropertyName(
  node: TSESTree.Identifier,
  ancestors: readonly TSESTree.Node[],
): boolean {
  const parent = ancestors[ancestors.length - 1];

  return (
    parent?.type === 'TSAsExpression' ||
    parent?.type === 'TSTypeReference' ||
    parent?.type === 'TSTypeQuery' ||
    (parent?.type === 'Property' && parent.key === node && !parent.computed) ||
    (parent?.type === 'MemberExpression' && parent.property === node && !parent.computed) ||
    (parent?.type === 'MethodDefinition' && parent.key === node && !parent.computed) ||
    parent?.type === 'ImportSpecifier' ||
    parent?.type === 'ImportDefaultSpecifier' ||
    parent?.type === 'ImportNamespaceSpecifier' ||
    parent?.type === 'ExportSpecifier' ||
    (parent?.type === 'FunctionDeclaration' && parent.id === node) ||
    (parent?.type === 'ClassDeclaration' && parent.id === node) ||
    (parent?.type === 'VariableDeclarator' && parent.id === node)
  );
}

function functionFromStatement(
  statement: TSESTree.Statement,
): TSESTree.FunctionDeclaration | undefined {
  if (statement.type === 'FunctionDeclaration') {
    return statement;
  }

  if (
    statement.type === 'ExportNamedDeclaration' &&
    statement.declaration?.type === 'FunctionDeclaration'
  ) {
    return statement.declaration;
  }

  if (
    statement.type === 'ExportDefaultDeclaration' &&
    statement.declaration.type === 'FunctionDeclaration'
  ) {
    return statement.declaration;
  }

  return undefined;
}

function collectDeclarations(
  body: TSESTree.Statement[],
  bindings: Map<string, Binding>,
): void {
  for (const statement of body) {
    if (statement.type === 'ImportDeclaration') {
      for (const specifier of statement.specifiers) {
        if (specifier.type === 'ImportDefaultSpecifier') {
          bindings.set(specifier.local.name, {
            name: specifier.local.name,
            kind: 'import',
            declaredLine: specifier.local.loc?.start.line ?? 0,
            referenced: true,
            node: specifier.local,
          });
        } else if (specifier.type === 'ImportNamespaceSpecifier') {
          bindings.set(specifier.local.name, {
            name: specifier.local.name,
            kind: 'import',
            declaredLine: specifier.local.loc?.start.line ?? 0,
            referenced: true,
            node: specifier.local,
          });
        } else if (specifier.type === 'ImportSpecifier' && specifier.importKind !== 'type') {
          bindings.set(specifier.local.name, {
            name: specifier.local.name,
            kind: 'import',
            declaredLine: specifier.local.loc?.start.line ?? 0,
            referenced: true,
            node: specifier.local,
          });
        }
      }
    }

    if (statement.type === 'VariableDeclaration') {
      for (const declarator of statement.declarations) {
        if (declarator.id.type !== 'Identifier') {
          continue;
        }

        const kind =
          statement.kind === 'const' || statement.kind === 'let' || statement.kind === 'var'
            ? statement.kind
            : 'let';

        bindings.set(declarator.id.name, {
          name: declarator.id.name,
          kind,
          declaredLine: declarator.id.loc?.start.line ?? 0,
          referenced: false,
          node: declarator.id,
        });
      }
    }
  }
}

function analyzeReferencesInStatement(
  statement: TSESTree.Statement,
  bindings: Map<string, Binding>,
  parentBindings: Map<string, Binding>,
  facts: ObservedFact[],
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): void {
  /**
   * Custom recursive walker (replaces walkAstWithAncestors) so we can prevent
   * traversal into nested FunctionExpression / ArrowFunctionExpression bodies.
   * Those are analyzed separately via analyzeFunctionLike with their own declaration
   * scope. Without this skip the walker would check inner-body identifiers against
   * the outer scope and emit false-positive undeclared-variable facts.
   */
  function walk(node: TSESTree.Node, ancestors: TSESTree.Node[]): void {
    // Nested function-like nodes get their own scope analysis.
    // Skip children to avoid double-processing (the inner body was already analyzed).
    if (
      ancestors.length > 0 &&
      (node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration')
    ) {
      const maybeFn = node as unknown as { params?: TSESTree.Parameter[]; body?: TSESTree.Node };
      if (maybeFn.body?.type === 'BlockStatement' && Array.isArray(maybeFn.params)) {
        analyzeFunctionLike(
          maybeFn.params,
          maybeFn.body as TSESTree.BlockStatement,
          bindings,
          facts,
          nodeIds,
          sourceText,
        );
      }
      return;
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.operator === '=' &&
      node.left.type === 'Identifier'
    ) {
      const binding = bindings.get(node.left.name);
      if (binding?.kind === 'const') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.reassign-const-binding',
            node: node.left,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: { binding: node.left.name },
          }),
        );
      }
    }

    if (node.type === 'UpdateExpression' && node.argument.type === 'Identifier') {
      const binding = bindings.get(node.argument.name);
      if (binding?.kind === 'const') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.reassign-const-binding',
            node: node.argument,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: { binding: node.argument.name },
          }),
        );
      }
    }

    if (node.type !== 'Identifier' || isTypeOrPropertyName(node, ancestors)) {
      // Not a bare variable reference — still recurse into children.
    } else {
      const name = node.name;
      const referenceLine = node.loc?.start.line ?? 0;
      const binding = bindings.get(name);

      if (binding) {
        binding.referenced = true;

        if (
          (binding.kind === 'let' || binding.kind === 'const') &&
          referenceLine < binding.declaredLine
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.used-before-definition',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: { binding: name },
            }),
          );
        }

        // Identifier node has no children worth recursing into.
        return;
      }

      if (RESTRICTED_GLOBALS.has(name)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.restricted-global-variable',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: { global: name },
          }),
        );
        return;
      }

      if (!GLOBAL_IDENTIFIERS.has(name) && !parentBindings.has(name)) {
        // Skip identifiers that are parameters of nested function/arrow expressions
        // (param bindings inside object literals are not captured by collectDeclarations)
        const isNestedFunctionParam = ancestors.some((ancestor) => {
          if (
            ancestor.type === 'ArrowFunctionExpression' ||
            ancestor.type === 'FunctionExpression'
          ) {
            const fn = ancestor as { params?: { type: string; name?: string }[] };
            return fn.params?.some(
              (param) => param.type === 'Identifier' && param.name === name,
            );
          }
          return false;
        });

        if (!isNestedFunctionParam) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.undeclared-variable',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: { binding: name },
            }),
          );
        }
      }

      return;
    }

    // Recurse into children (same logic as walkAstWithAncestors).
    for (const value of Object.values(node)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (isNode(entry)) {
            walk(entry, [...ancestors, node]);
          }
        }
        continue;
      }

      if (isNode(value)) {
        walk(value, [...ancestors, node]);
      }
    }
  }

  walk(statement, []);
}

function analyzeScopeBlock(
  body: TSESTree.Statement[],
  parentBindings: Map<string, Binding>,
  facts: ObservedFact[],
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): void {
  const bindings = new Map<string, Binding>(parentBindings);
  collectDeclarations(body, bindings);

  for (const statement of body) {
    const functionDeclaration = functionFromStatement(statement);
    if (functionDeclaration) {
      if (functionDeclaration.body.type === 'BlockStatement') {
        analyzeFunctionLike(
          functionDeclaration.params,
          functionDeclaration.body,
          bindings,
          facts,
          nodeIds,
          sourceText,
        );
      }
      continue;
    }

    analyzeReferencesInStatement(
      statement,
      bindings,
      parentBindings,
      facts,
      nodeIds,
      sourceText,
    );
  }

  for (const binding of bindings.values()) {
    if (!binding.referenced && binding.kind !== 'import' && !parentBindings.has(binding.name)) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.unused-variable',
          node: binding.node,
          nodeIds,
          text: getNodeText(binding.node, sourceText),
          props: { binding: binding.name },
        }),
      );
    }
  }
}

function analyzeFunctionLike(
  params: TSESTree.Parameter[],
  body: TSESTree.BlockStatement,
  parentBindings: Map<string, Binding>,
  facts: ObservedFact[],
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): void {
  const bindings = new Map<string, Binding>(parentBindings);

  for (const param of params) {
    if (param.type === 'Identifier') {
      bindings.set(param.name, {
        name: param.name,
        kind: 'param',
        declaredLine: param.loc?.start.line ?? 0,
        referenced: true,
        node: param,
      });
    }
  }

  analyzeScopeBlock(body.body, bindings, facts, nodeIds, sourceText);
}

export const collectTypescriptScopeCorrectnessFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const { program, sourceText, nodeIds } = context;
  const facts: ObservedFact[] = [];

  analyzeScopeBlock(program.body, new Map(), facts, nodeIds, sourceText);

  const usedNames = new Set<string>();

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== 'Identifier') {
      return;
    }

    for (let i = ancestors.length - 1; i >= 0; i -= 1) {
      if (ancestors[i]?.type === 'ImportDeclaration') {
        return;
      }
    }

    usedNames.add(node.name);
  });

  for (const statement of program.body) {
    if (statement.type !== 'ImportDeclaration') {
      continue;
    }

    if (statement.specifiers.length === 0) {
      continue;
    }

    if (statement.importKind === 'type') {
      continue;
    }

    const allUnused = statement.specifiers.every((specifier) => {
      let localName: string | undefined;

      if (specifier.type === 'ImportDefaultSpecifier') {
        localName = specifier.local.name;
      } else if (specifier.type === 'ImportNamespaceSpecifier') {
        localName = specifier.local.name;
      } else if (specifier.type === 'ImportSpecifier') {
        localName = specifier.local.name;
      }

      if (!localName) {
        return true;
      }

      return !usedNames.has(localName);
    });

    if (allUnused) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.extraneous-import',
          node: statement,
          nodeIds,
          text: getNodeText(statement, sourceText),
          props: {},
        }),
      );
    }
  }

  return facts;
};
