import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  walkAstWithAncestors,
  type TypeScriptFactDetectorContext,
} from '../shared';

import { FACT_KINDS } from './constants';

function isModuleScopeParent(node: TSESTree.Node | undefined): boolean {
  return (
    node?.type === 'Program' ||
    node?.type === 'ExportNamedDeclaration' ||
    node?.type === 'TSModuleDeclaration'
  );
}

/** `export let` / `export var` and module-scope reassignment of exported bindings. */
export function collectMutableModuleExportFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const exportedNames = new Set<string>();
  const exportNodes = new Map<string, TSESTree.Node>();
  const reported = new Set<string>();

  walkAstWithAncestors(context.program, (node) => {
    if (node.type !== 'ExportNamedDeclaration') {
      return;
    }

    const declaration = node.declaration;

    if (
      declaration?.type === 'VariableDeclaration' &&
      declaration.kind !== 'const'
    ) {
      for (const declarator of declaration.declarations) {
        if (declarator.id.type !== 'Identifier') {
          continue;
        }

        exportedNames.add(declarator.id.name);
        exportNodes.set(declarator.id.name, node);
      }
    }

    for (const specifier of node.specifiers) {
      if (specifier.local.type !== 'Identifier') {
        continue;
      }

      exportedNames.add(specifier.local.name);
      exportNodes.set(specifier.local.name, node);
    }
  });

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (
      node.type === 'VariableDeclaration' &&
      node.kind !== 'const' &&
      isModuleScopeParent(ancestors.at(-1))
    ) {
      for (const declarator of node.declarations) {
        if (declarator.id.type !== 'Identifier') {
          continue;
        }

        const exportAncestor = ancestors.find(
          (ancestor) => ancestor.type === 'ExportNamedDeclaration',
        );

        if (exportAncestor) {
          exportedNames.add(declarator.id.name);
          exportNodes.set(declarator.id.name, exportAncestor);
        }
      }
    }

    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'Identifier' ||
      node.operator !== '=' ||
      !isModuleScopeParent(ancestors.at(-1)) ||
      !exportedNames.has(node.left.name)
    ) {
      return;
    }

    const binding = node.left.name;

    if (reported.has(binding)) {
      return;
    }

    reported.add(binding);

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.mutableModuleExport,
        node: exportNodes.get(binding) ?? node,
        nodeIds: context.nodeIds,
        text: binding,
        props: {
          binding,
          reason: 'reassigned-export',
        },
      }),
    );
  });

  for (const [binding, exportNode] of exportNodes) {
    if (reported.has(binding)) {
      continue;
    }

    reported.add(binding);

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.mutableModuleExport,
        node: exportNode,
        nodeIds: context.nodeIds,
        text: binding,
        props: {
          binding,
          reason: 'mutable-export',
        },
      }),
    );
  }

  return facts;
}
