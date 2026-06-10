import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { createObservedFact, walkAst, walkAstWithAncestors } from './shared';
import type { TypeScriptFactDetectorContext } from './shared';

const CLIENT_SIDE_HOOKS = new Set([
  'beforeMount',
  'mounted',
  'beforeUpdate',
  'updated',
  'activated',
  'deactivated',
  'beforeDestroy',
  'destroyed',
]);

const SERVER_SIDE_HOOKS = new Set([
  'created',
  'beforeCreate',
]);

const VUE_LIFECYCLE_HOOKS = new Set([
  ...CLIENT_SIDE_HOOKS,
  ...SERVER_SIDE_HOOKS,
]);

const BROWSER_GLOBALS = new Set(['window', 'document']);

const NUXT_PROCESS_PROPERTIES = new Set(['server', 'client', 'browser']);

function isNuxtProcessAccess(node: TSESTree.Node): boolean {
  if (
    node.type === 'MemberExpression' &&
    !node.computed &&
    node.object.type === 'Identifier' &&
    node.object.name === 'process' &&
    node.property.type === 'Identifier' &&
    NUXT_PROCESS_PROPERTIES.has(node.property.name)
  ) {
    return true;
  }

  return false;
}

function isBrowserGlobal(node: TSESTree.Node): boolean {
  return node.type === 'Identifier' && BROWSER_GLOBALS.has(node.name);
}

function isVueComponentExport(program: TSESTree.Program): boolean {
  let found = false;

  walkAst(program, (node) => {
    if (found) return;

    if (
      node.type === 'ExportDefaultDeclaration' &&
      node.declaration.type === 'ObjectExpression'
    ) {
      for (const property of node.declaration.properties) {
        if (
          property.type === 'Property' &&
          !property.computed &&
          property.key.type === 'Identifier' &&
          VUE_LIFECYCLE_HOOKS.has(property.key.name)
        ) {
          found = true;
          return;
        }
      }
    }
  });

  return found;
}

function findEnclosingObjectMethod(
  ancestors: readonly TSESTree.Node[],
): { methodName: string; ancestors: readonly TSESTree.Node[] } | undefined {
  for (let i = ancestors.length - 1; i >= 0; i -= 1) {
    const ancestor = ancestors[i];

    if (ancestor.type === 'Property' && ancestor.key.type === 'Identifier') {
      const parent = ancestors[i - 1];
      if (parent?.type === 'ObjectExpression') {
        return { methodName: ancestor.key.name, ancestors: ancestors.slice(0, i) };
      }
    }
  }

  return undefined;
}

function collectProcessAccessInClientHooks(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!isVueComponentExport(context.program)) {
    return facts;
  }

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (!isNuxtProcessAccess(node)) {
      return;
    }

    const methodInfo = findEnclosingObjectMethod(ancestors);
    if (!methodInfo) {
      return;
    }

    const { methodName } = methodInfo;

    if (!CLIENT_SIDE_HOOKS.has(methodName)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'framework.nuxt.process-hook-in-client-side',
        node,
        nodeIds: context.nodeIds,
        text: context.sourceText.slice(node.range[0], node.range[1]),
        props: {
          hookName: methodName,
          processProp:
            node.type === 'MemberExpression' && node.property.type === 'Identifier'
              ? node.property.name
              : undefined,
        },
      }),
    );
  });

  return facts;
}

function collectBrowserGlobalsInServerHooks(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!isVueComponentExport(context.program)) {
    return facts;
  }

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (!isBrowserGlobal(node)) {
      return;
    }

    const methodInfo = findEnclosingObjectMethod(ancestors);
    if (!methodInfo) {
      return;
    }

    const { methodName } = methodInfo;

    if (!SERVER_SIDE_HOOKS.has(methodName)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'framework.nuxt.browser-global-in-created-lifecycle',
        node,
        nodeIds: context.nodeIds,
        text: context.sourceText.slice(node.range[0], node.range[1]),
        props: {
          hookName: methodName,
          browserGlobal: node.type === 'Identifier' ? node.name : undefined,
        },
      }),
    );
  });

  return facts;
}

export function collectVueNuxtLifecycleFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectProcessAccessInClientHooks(context),
    ...collectBrowserGlobalsInServerHooks(context),
  ];
}
