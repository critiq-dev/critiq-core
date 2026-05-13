import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import { getJsxTagName } from './jsx-elements';

const FACT_UNCONTROLLED = 'ui.react.uncontrolled-controlled-input';

/** Detects inputs that mix controlled and uncontrolled props. */
export function collectUncontrolledControlledInputFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXElement') {
      return;
    }

    const opening = node.openingElement;
    const tag = getJsxTagName(opening.name, context.sourceText);

    if (!tag || tag.toLowerCase() !== 'input') {
      return;
    }

    let hasValue = false;
    let hasDefaultValue = false;

    for (const attr of opening.attributes) {
      if (
        attr.type === 'JSXAttribute' &&
        attr.name.type === 'JSXIdentifier'
      ) {
        if (attr.name.name === 'value') {
          hasValue = true;
        }

        if (attr.name.name === 'defaultValue') {
          hasDefaultValue = true;
        }
      }
    }

    if (!hasValue || !hasDefaultValue) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_UNCONTROLLED,
        node: opening.name,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(opening.name, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}
