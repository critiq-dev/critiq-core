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
  hasPointerOrNonClickKeyHandler,
} from './jsx-event-handlers';
import {
  getJsxBooleanAttr,
  hasJsxAttribute,
  getJsxNumericAttr,
  getJsxStringAttr,
} from './jsx-attributes';
import {
  getJsxTagName,
  INTERACTIVE_ROLES,
  isDecorativeImage,
  isIntrinsicJsxTag,
  isNativeInteractiveElement,
  isSemanticElementWithInteractiveRole,
} from './jsx-elements';

const FACT_CLICK_WITHOUT_KEYBOARD = 'ui.react.click-without-keyboard-handler';
const FACT_MISSING_ALT_TEXT = 'ui.react.missing-alt-text';
const FACT_POSITIVE_TABINDEX = 'ui.react.positive-tabindex';
const FACT_ANCHOR_INVALID_HREF = 'ui.react.anchor-with-invalid-href';
const FACT_ACTIVEDESCENDANT_HOST = 'ui.react.activedescendant-host-not-focusable';
const FACT_WIDGET_ROLE_NO_TABINDEX = 'ui.react.widget-role-without-tabindex';
const FACT_SEMANTIC_WITH_WIDGET_ROLE = 'ui.react.semantic-static-with-interactive-role';
const FACT_KEYBOARD_NO_WIDGET_ROLE = 'ui.react.keyboard-interaction-without-widget-role';
const FACT_STATIC_POINTER_OR_KEY = 'ui.react.non-interactive-with-pointer-or-key-handler-without-role';

const ANCHOR_WIDGET_ROLES = new Set([
  'button',
  'checkbox',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'radio',
  'switch',
  'tab',
]);

function isHrefInvalidAsLink(href: string | undefined): boolean {
  if (href === undefined) {
    return true;
  }

  if (href === '[expression]') {
    return false;
  }

  const trimmed = href.trim();

  if (trimmed.length === 0) {
    return true;
  }

  const lower = trimmed.toLowerCase();

  if (lower === '#') {
    return true;
  }

  return lower.startsWith('javascript:');
}

function shouldSkipInvalidAnchorCheck(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  const role = getJsxStringAttr(opening, 'role')?.toLowerCase();

  return Boolean(role && ANCHOR_WIDGET_ROLES.has(role));
}

function getInteractiveRoleLower(
  opening: TSESTree.JSXOpeningElement,
): string | undefined {
  const role = getJsxStringAttr(opening, 'role')?.toLowerCase();

  return role && INTERACTIVE_ROLES.has(role) ? role : undefined;
}

function isTabIndexZeroOrPositive(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  const tabIndex =
    getJsxNumericAttr(opening, 'tabIndex') ??
    getJsxNumericAttr(opening, 'tabindex');

  return tabIndex !== undefined && tabIndex >= 0;
}

function shouldSkipWidgetRoleFocusRule(
  opening: TSESTree.JSXOpeningElement,
  lowerTagName: string,
): boolean {
  if (['input', 'button', 'textarea', 'select'].includes(lowerTagName)) {
    return true;
  }

  if (lowerTagName === 'a') {
    const href = getJsxStringAttr(opening, 'href');

    if (
      href !== undefined &&
      href !== '[expression]' &&
      !isHrefInvalidAsLink(href)
    ) {
      return true;
    }
  }

  return false;
}

function isActiveDescendantHostKeyboardFocusable(
  opening: TSESTree.JSXOpeningElement,
  lowerTagName: string,
): boolean {
  if (['input', 'button', 'textarea', 'select', 'summary'].includes(lowerTagName)) {
    return true;
  }

  if (lowerTagName === 'a') {
    const href = getJsxStringAttr(opening, 'href');

    if (href === undefined || href === '[expression]') {
      return isTabIndexZeroOrPositive(opening);
    }

    return !isHrefInvalidAsLink(href);
  }

  return isTabIndexZeroOrPositive(opening);
}

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

function isHiddenOrPresentational(opening: TSESTree.JSXOpeningElement): boolean {
  return (
    getJsxBooleanAttr(opening, 'aria-hidden') === true ||
    getJsxStringAttr(opening, 'role')?.toLowerCase() === 'presentation' ||
    getJsxStringAttr(opening, 'role')?.toLowerCase() === 'none'
  );
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

    if (
      lowerTagName === 'a' &&
      isIntrinsicJsxTag(tagName) &&
      !shouldSkipInvalidAnchorCheck(opening)
    ) {
      const href = getJsxStringAttr(opening, 'href');

      if (isHrefInvalidAsLink(href)) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_ANCHOR_INVALID_HREF,
            node: opening.name,
            nodeIds: context.nodeIds,
            props: {
              tag: tagName,
            },
            text: getNodeText(opening.name, context.sourceText),
          }),
        );
      }
    }

    if (
      hasJsxAttribute(opening, 'aria-activedescendant') &&
      isIntrinsicJsxTag(tagName) &&
      !isActiveDescendantHostKeyboardFocusable(opening, lowerTagName)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_ACTIVEDESCENDANT_HOST,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tag: tagName,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }

    const interactiveRole = getInteractiveRoleLower(opening);

    if (
      interactiveRole &&
      isIntrinsicJsxTag(tagName) &&
      !shouldSkipWidgetRoleFocusRule(opening, lowerTagName) &&
      !isTabIndexZeroOrPositive(opening) &&
      !isSemanticElementWithInteractiveRole(lowerTagName, interactiveRole)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_WIDGET_ROLE_NO_TABINDEX,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tag: tagName,
            role: interactiveRole,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }

    const roleLower = getJsxStringAttr(opening, 'role')?.toLowerCase();

    if (
      roleLower &&
      isIntrinsicJsxTag(tagName) &&
      isSemanticElementWithInteractiveRole(lowerTagName, roleLower)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_SEMANTIC_WITH_WIDGET_ROLE,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tag: tagName,
            role: roleLower,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }

    if (
      isIntrinsicJsxTag(tagName) &&
      !isKeyboardInteractiveByDefault(opening, lowerTagName) &&
      !isNativeInteractiveElement(lowerTagName) &&
      hasClickHandler(opening) &&
      hasKeyboardHandler(opening) &&
      !interactiveRole &&
      !isHiddenOrPresentational(opening)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_KEYBOARD_NO_WIDGET_ROLE,
          node: opening.name,
          nodeIds: context.nodeIds,
          props: {
            tag: tagName,
          },
          text: getNodeText(opening.name, context.sourceText),
        }),
      );
    }

    if (
      isIntrinsicJsxTag(tagName) &&
      !isKeyboardInteractiveByDefault(opening, lowerTagName) &&
      !isNativeInteractiveElement(lowerTagName) &&
      hasPointerOrNonClickKeyHandler(opening) &&
      !hasClickHandler(opening) &&
      !interactiveRole &&
      !isHiddenOrPresentational(opening)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_STATIC_POINTER_OR_KEY,
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
