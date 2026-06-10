import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { createObservedFact, walkAst } from './shared';
import type { TypeScriptFactDetectorContext } from './shared';

function collectDuplicateExportFactsImpl(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;
  const exportNames = new Map<string, TSESTree.Node>();
  let defaultExportCount = 0;

  walkAst(program, (node) => {
    if (node.type === 'ExportDefaultDeclaration') {
      defaultExportCount += 1;

      if (defaultExportCount > 1) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.duplicate-export',
            node,
            nodeIds,
            text: sourceText.slice(node.range[0], node.range[1]),
            props: {
              duplicateName: 'default',
              reason: 'multiple-default-exports',
            },
          }),
        );
      }

      return;
    }

    if (node.type !== 'ExportNamedDeclaration') {
      return;
    }

    const declaration = node.declaration;
    if (declaration?.type === 'VariableDeclaration') {
      for (const declarator of declaration.declarations) {
        if (declarator.id.type === 'Identifier') {
          const name = declarator.id.name;
          const prior = exportNames.get(name);
          if (prior) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.duplicate-export',
                node,
                nodeIds,
                text: sourceText.slice(node.range[0], node.range[1]),
                props: {
                  duplicateName: name,
                  reason: 'named-export-duplicate',
                },
              }),
            );
          } else {
            exportNames.set(name, node);
          }
        }
      }
    }

    if (
      declaration?.type === 'FunctionDeclaration' ||
      declaration?.type === 'ClassDeclaration'
    ) {
      if (declaration.id) {
        const name = declaration.id.name;
        const prior = exportNames.get(name);
        if (prior) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.duplicate-export',
              node,
              nodeIds,
              text: sourceText.slice(node.range[0], node.range[1]),
              props: {
                duplicateName: name,
                reason: 'named-export-duplicate',
              },
            }),
          );
        } else {
          exportNames.set(name, node);
        }
      }
    }

    for (const specifier of node.specifiers) {
      const exported =
        specifier.exported.type === 'Identifier'
          ? specifier.exported.name
          : specifier.exported.value;

      const prior = exportNames.get(exported);
      if (prior) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.duplicate-export',
            node,
            nodeIds,
            text: sourceText.slice(node.range[0], node.range[1]),
            props: {
              duplicateName: exported,
              reason: 'named-export-duplicate',
            },
          }),
        );
      } else {
        exportNames.set(exported, node);
      }
    }
  });

  return facts;
}

export function collectDuplicateExportFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return collectDuplicateExportFactsImpl(context);
}
