import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { createObservedFact, walkAst } from './shared';
import type { TypeScriptFactDetectorContext } from './shared';

const CUSTOM_DOCUMENT_PATH_PATTERN = /(^|\/)pages\/_document\.(ts|tsx|js|jsx)$/;
const SRC_CUSTOM_DOCUMENT_PATH_PATTERN = /(^|\/)src\/pages\/_document\.(ts|tsx|js|jsx)$/;
const NEXT_DOCUMENT_IMPORT = 'next/document';
const NEXT_HEAD_IMPORT = 'next/head';

function isCustomDocumentPath(path: string): boolean {
  return CUSTOM_DOCUMENT_PATH_PATTERN.test(path) || SRC_CUSTOM_DOCUMENT_PATH_PATTERN.test(path);
}

function collectDocumentImportOutsideCustomDocument(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (isCustomDocumentPath(context.path)) {
    return facts;
  }

  walkAst(context.program, (node) => {
    if (node.type !== 'ImportDeclaration') {
      return;
    }

    if (node.source.value !== NEXT_DOCUMENT_IMPORT) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'framework.next.document-import-outside-custom-document',
        node,
        nodeIds: context.nodeIds,
        text: context.sourceText.slice(node.range[0], node.range[1]),
        props: {
          moduleSpecifier: NEXT_DOCUMENT_IMPORT,
        },
      }),
    );
  });

  return facts;
}

function collectHeadImportInCustomDocument(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!isCustomDocumentPath(context.path)) {
    return facts;
  }

  walkAst(context.program, (node) => {
    if (node.type !== 'ImportDeclaration') {
      return;
    }

    if (node.source.value !== NEXT_HEAD_IMPORT) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'framework.next.head-import-in-custom-document',
        node,
        nodeIds: context.nodeIds,
        text: context.sourceText.slice(node.range[0], node.range[1]),
        props: {
          moduleSpecifier: NEXT_HEAD_IMPORT,
        },
      }),
    );
  });

  return facts;
}

export function collectNextImportRulesFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectDocumentImportOutsideCustomDocument(context),
    ...collectHeadImportInCustomDocument(context),
  ];
}
