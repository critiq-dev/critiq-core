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
  'TypeError',
  'RangeError',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'Promise',
  'JSON',
  'Math',
  'console',
  'globalThis',
  'global',
  'self',
  'window',
  'document',
  'module',
  'exports',
  'require',
  'process',
  '__dirname',
  '__filename',
  'Buffer',
  'ArrayBuffer',
  'SharedArrayBuffer',
  'DataView',
  'Int8Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'Int16Array',
  'Uint16Array',
  'Int32Array',
  'Uint32Array',
  'Float32Array',
  'Float64Array',
  'BigInt64Array',
  'BigUint64Array',
  'Atomics',
  'WebAssembly',
  'encodeURI',
  'encodeURIComponent',
  'decodeURI',
  'decodeURIComponent',
  'setTimeout',
  'setInterval',
  'clearTimeout',
  'clearInterval',
  'setImmediate',
  'queueMicrotask',
  'unescape',
]);

const RESTRICTED_GLOBALS = new Set([
  'event',
  'name',
  'status',
  'parent',
  'top',
  'frames',
  'opener',
  'closed',
  'length',
  'external',
]);

type Binding = {
  name: string;
  kind: 'var' | 'let' | 'const' | 'param' | 'import' | 'function';
  declaredLine: number;
  referenced: boolean;
  node: TSESTree.Node;
  /** True when the binding is a `var undefined;` (or `var undefined = undefined;`) pre-ES5 anti-mutation guard. */
  isUndefinedGuard?: boolean;
};

function isTypeOrPropertyName(
  node: TSESTree.Identifier,
  ancestors: readonly TSESTree.Node[],
): boolean {
  const parent = ancestors[ancestors.length - 1];

  return (
    parent?.type === 'TSTypeReference' ||
    parent?.type === 'TSTypeQuery' ||
    (parent?.type === 'Property' && parent.key === node && !parent.computed) ||
    (parent?.type === 'PropertyDefinition' && parent.key === node && !parent.computed) ||
    (parent?.type === 'MemberExpression' && parent.property === node && !parent.computed) ||
    (parent?.type === 'MethodDefinition' && parent.key === node && !parent.computed) ||
    (parent?.type === 'TSAbstractMethodDefinition' && parent.key === node && !parent.computed) ||
    (parent?.type === 'TSPropertySignature' && parent.key === node && !parent.computed) ||
    parent?.type === 'ImportSpecifier' ||
    parent?.type === 'ImportDefaultSpecifier' ||
    parent?.type === 'ImportNamespaceSpecifier' ||
    parent?.type === 'ExportSpecifier' ||
    (parent?.type === 'FunctionDeclaration' && parent.id === node) ||
    (parent?.type === 'ClassDeclaration' && parent.id === node) ||
    (parent?.type === 'VariableDeclarator' && parent.id === node) ||
    (parent?.type === 'TSInterfaceDeclaration' && parent.id === node) ||
    (parent?.type === 'TSTypeAliasDeclaration' && parent.id === node) ||
    (parent?.type === 'TSEnumDeclaration' && parent.id === node) ||
    parent?.type === 'TSFunctionType' ||
    parent?.type === 'TSConstructorType' ||
    parent?.type === 'TSMethodSignature' ||
    parent?.type === 'TSCallSignatureDeclaration' ||
    parent?.type === 'TSConstructSignatureDeclaration'
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

        // Pre-ES5 anti-mutation guard: `var undefined;` or `var undefined = undefined;`
        const isUndefinedGuard =
          kind === 'var' &&
          declarator.id.name === 'undefined' &&
          (!declarator.init ||
            (declarator.init.type === 'Identifier' && declarator.init.name === 'undefined'));

        bindings.set(declarator.id.name, {
          name: declarator.id.name,
          kind,
          declaredLine: declarator.id.loc?.start.line ?? 0,
          referenced: false,
          node: declarator.id,
          isUndefinedGuard,
        });
      }
    }

    const fnDecl = functionFromStatement(statement);
    if (fnDecl?.id) {
      bindings.set(fnDecl.id.name, {
        name: fnDecl.id.name,
        kind: 'function',
        declaredLine: fnDecl.id.loc?.start.line ?? 0,
        referenced: true,
        node: fnDecl.id,
      });
    }
  }

  collectNestedVarDeclarations(body, bindings);
}

function collectNestedVarDeclarations(
  body: TSESTree.Statement[],
  bindings: Map<string, Binding>,
): void {
  const queue = [...body];

  while (queue.length > 0) {
    const statement = queue.pop()!;

    if (statement.type === 'VariableDeclaration') {
      const isBlockScoped = statement.kind === 'let' || statement.kind === 'const';
      if (statement.kind === 'var' || isBlockScoped) {
        for (const declarator of statement.declarations) {
          if (declarator.id.type !== 'Identifier') {
            continue;
          }

          if (!bindings.has(declarator.id.name)) {
            // Pre-ES5 anti-mutation guard: `var undefined;` or `var undefined = undefined;`
            const isUndefinedGuard =
              statement.kind === 'var' &&
              declarator.id.name === 'undefined' &&
              (!declarator.init ||
                (declarator.init.type === 'Identifier' && declarator.init.name === 'undefined'));

            bindings.set(declarator.id.name, {
              name: declarator.id.name,
              kind: statement.kind as Binding['kind'],
              declaredLine: declarator.id.loc?.start.line ?? 0,
              referenced: false,
              node: declarator.id,
              isUndefinedGuard,
            });
          }
        }
      }
    }

    // Enqueue child statements from nested blocks (recursive for if/for/while/switch/etc.)
    for (const value of Object.values(statement)) {
      if (Array.isArray(value)) {
        for (const entry of value) {
          if (entry && typeof entry === 'object' && 'type' in entry &&
              typeof (entry as { type: unknown }).type === 'string') {
            const node = entry as TSESTree.Node;
            if (
              (node.type.endsWith('Statement') || node.type === 'VariableDeclaration') &&
              node !== statement
            ) {
              queue.push(node as TSESTree.Statement);
            }
            if (node.type === 'SwitchCase') {
              const sc = node as TSESTree.SwitchCase;
              queue.push(...sc.consequent);
            }
          }
        }
      } else if (value && typeof value === 'object' && 'type' in value &&
                 typeof (value as { type: unknown }).type === 'string') {
        const node = value as TSESTree.Node;
        // Enqueue statement containers (e.g. for-loop body, if-body) so nested
        // declarations inside those blocks are discovered. Must check before
        // the VariableDeclaration handler so we don't miss compound statements.
        if (
          (node.type.endsWith('Statement') || node.type === 'VariableDeclaration') &&
          node !== statement
        ) {
          queue.push(node as TSESTree.Statement);
        }
        // Catch variable declarations in non-array positions (e.g. for-loop init,
        // for...of / for...in left). Handles var, let, and const.
        if (node.type === 'VariableDeclaration') {
          const vd = node as TSESTree.VariableDeclaration;
          const isBindableKind = vd.kind === 'var' || vd.kind === 'let' || vd.kind === 'const';
          if (isBindableKind) {
            for (const declarator of vd.declarations) {
              if (declarator.id.type !== 'Identifier') {
                continue;
              }
              if (!bindings.has(declarator.id.name)) {
                bindings.set(declarator.id.name, {
                  name: declarator.id.name,
                  kind: vd.kind as Binding['kind'],
                  declaredLine: declarator.id.loc?.start.line ?? 0,
                  referenced: false,
                  node: declarator.id,
                });
              }
            }
          }
        }
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
  function walk(
    node: TSESTree.Node,
    ancestors: TSESTree.Node[],
    scopeBindings?: Map<string, Binding>,
  ): void {
    const effectiveBindings = scopeBindings ?? bindings;
    // Nested function-like nodes get their own scope analysis.
    // Skip children to avoid double-processing (the inner body was already analyzed).
    if (
      ancestors.length > 0 &&
      (node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration')
    ) {
      const maybeFn = node as unknown as { params?: TSESTree.Parameter[]; body?: TSESTree.Node };
      if (Array.isArray(maybeFn.params)) {
        if (maybeFn.body?.type === 'BlockStatement') {
          analyzeFunctionLike(
            maybeFn.params,
            maybeFn.body as TSESTree.BlockStatement,
            effectiveBindings,
            facts,
            nodeIds,
            sourceText,
          );
        } else if (maybeFn.body) {
          const childBindings = new Map(effectiveBindings);
          for (const param of maybeFn.params) {
            if (param.type === 'Identifier') {
              childBindings.set(param.name, {
                name: param.name,
                kind: 'param',
                declaredLine: param.loc?.start.line ?? 0,
                referenced: true,
                node: param,
              });
            }
          }
          walk(maybeFn.body, [...ancestors, node], childBindings);
        }
      }
      return;
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.operator === '=' &&
      node.left.type === 'Identifier'
    ) {
      const binding = effectiveBindings.get(node.left.name);
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
      const binding = effectiveBindings.get(node.argument.name);
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
      const binding = effectiveBindings.get(name);

      if (binding) {
        binding.referenced = true;

        if (
          binding.kind !== 'function' &&
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

      if (RESTRICTED_GLOBALS.has(name) && !effectiveBindings.has(name) && !parentBindings.has(name)) {
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
            walk(entry, [...ancestors, node], scopeBindings);
          }
        }
        continue;
      }

      if (isNode(value)) {
        walk(value, [...ancestors, node], scopeBindings);
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
      // `var undefined;` is a well-known pre-ES5 anti-mutation guard — skip it.
      if (binding.isUndefinedGuard) {
        continue;
      }

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
