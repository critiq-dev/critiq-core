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
  hasClickHandler,
  hasKeyboardHandler,
} from './jsx-event-handlers';
import {
  getJsxBooleanAttr,
  hasJsxAttribute,
  getJsxNumericAttr,
  getJsxStringAttr,
} from './jsx-attributes';
import {
  getJsxTagName,
  isDecorativeImage,
  isIntrinsicJsxTag,
  isNativeInteractiveElement,
} from './jsx-elements';

const FACT_CLICK_WITHOUT_KEYBOARD = 'ui.react.click-without-keyboard-handler';
const FACT_MISSING_ALT_TEXT = 'ui.react.missing-alt-text';
const FACT_POSITIVE_TABINDEX = 'ui.react.positive-tabindex';

function getAltTextStatus(
  opening: TSESTree.JSXOpeningElement,
): 'missing' | 'empty' | 'present' {
  const alt = getJsxStringAttr(opening, 'alt');

  if (alt === undefined) {
    return 'missing';
  }

  if (alt === '[expression]') {
    return 'present';
  }

  return alt.trim().length === 0 ? 'empty' : 'present';
}

function isKeyboardInteractiveByDefault(
  opening: TSESTree.JSXOpeningElement,
  lowerTagName: string,
): boolean {
  if (lowerTagName === 'a') {
    return hasJsxAttribute(opening, 'href');
  }

  return isNativeInteractiveElement(lowerTagName);
}

/** Detects JSX accessibility issues added in the DeepSource parity wave. */
export function collectAccessibilityParityFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXElement') {
      return;
    }

    const opening = node.openingElement;
    const tagName = getJsxTagName(opening.name, context.sourceText);

    if (!tagName) {
      return;
    }

    const lowerTagName = tagName.toLowerCase();

    if (lowerTagName === 'img') {
      const altStatus = getAltTextStatus(opening);

      if (
        altStatus !== 'present' &&
        !(altStatus === 'empty' && isDecorativeImage(opening))
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_MISSING_ALT_TEXT,
            node: opening.name,
            nodeIds: context.nodeIds,
            props: {
              tag: tagName,
              decorative: isDecorativeImage(opening),
            },
            text: getNodeText(opening.name, context.sourceText),
          }),
        );
      }
    }

    const tabIndex =
      getJsxNumericAttr(opening, 'tabIndex') ??
      getJsxNumericAttr(opening, 'tabindex');

    if (tabIndex !== undefined && tabIndex > 0) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_POSITIVE_TABINDEX,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tabIndex,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }

    if (
      isIntrinsicJsxTag(tagName) &&
      !isKeyboardInteractiveByDefault(opening, lowerTagName) &&
      hasClickHandler(opening) &&
      !hasKeyboardHandler(opening) &&
      getJsxBooleanAttr(opening, 'aria-hidden') !== true &&
      getJsxStringAttr(opening, 'role')?.toLowerCase() !== 'presentation'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_CLICK_WITHOUT_KEYBOARD,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tag: tagName,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }
  });

  return dedupeFactsByRange(facts);
}
