import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import {
  getJsxTagName,
  jsxHasAccessibleNameAttr,
  jsxHasNonEmptyTextContent,
  shouldCheckAccessibleName,
} from './jsx-elements';

const FACT_A11Y_NAME = 'ui.react.missing-accessible-name';

/** Detects interactive elements that lack an accessible name. */
export function collectMissingAccessibleNameFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXElement') {
      return;
    }

    const opening = node.openingElement;

    if (
      !shouldCheckAccessibleName(opening, context.sourceText) ||
      jsxHasAccessibleNameAttr(opening) ||
      jsxHasNonEmptyTextContent(node)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_A11Y_NAME,
        node: opening.name as TSESTree.Node,
        nodeIds: context.nodeIds,
        props: {
          tag: getJsxTagName(opening.name, context.sourceText),
        },
        text: getNodeText(opening.name as TSESTree.Node, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}
