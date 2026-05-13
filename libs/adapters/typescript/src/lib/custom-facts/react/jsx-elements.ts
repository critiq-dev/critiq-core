import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText } from '../shared';
import {
  getJsxBooleanAttr,
  getJsxStringAttr,
} from './jsx-attributes';

const NATIVE_INTERACTIVE_TAGS = new Set([
  'a',
  'button',
  'input',
  'option',
  'select',
  'textarea',
]);

export const INTERACTIVE_ROLES = new Set([
  'button',
  'checkbox',
  'link',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'option',
  'radio',
  'slider',
  'spinbutton',
  'switch',
  'tab',
  'textbox',
]);

/** Phrasing or landmark tags that should not masquerade as interactive widgets. */
const SEMANTIC_TAGS_DISCOURAGED_WITH_WIDGET_ROLE = new Set([
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'p',
  'blockquote',
  'figcaption',
  'caption',
  'dt',
  'label',
  'legend',
]);

/** Returns the rendered tag text for an intrinsic or member JSX opening element. */
export function getJsxTagName(
  name: TSESTree.JSXOpeningElement['name'],
  sourceText: string,
): string | undefined {
  if (name.type === 'JSXIdentifier') {
    return name.name;
  }

  if (name.type === 'JSXMemberExpression') {
    return getNodeText(name, sourceText);
  }

  return undefined;
}

/** Returns only JSX children that are direct elements inside a fragment. */
export function flatJsxElementsInFragment(
  fragment: TSESTree.JSXFragment,
): TSESTree.JSXElement[] {
  return fragment.children.filter(
    (child): child is TSESTree.JSXElement => child.type === 'JSXElement',
  );
}

/** Checks whether an intrinsic JSX tag is natively keyboard interactive. */
export function isNativeInteractiveElement(tagName: string): boolean {
  return NATIVE_INTERACTIVE_TAGS.has(tagName.toLowerCase());
}

/** Treats only lowercase intrinsic JSX tag names as DOM elements. */
export function isIntrinsicJsxTag(tagName: string): boolean {
  return tagName === tagName.toLowerCase();
}

/** Checks whether JSX children contain visible text content. */
export function jsxHasNonEmptyTextContent(element: TSESTree.JSXElement): boolean {
  for (const child of element.children) {
    if (child.type === 'JSXText' && child.value.trim().length > 0) {
      return true;
    }

    if (
      child.type === 'JSXExpressionContainer' &&
      child.expression.type === 'Literal' &&
      typeof child.expression.value === 'string' &&
      child.expression.value.trim().length > 0
    ) {
      return true;
    }

    if (child.type === 'JSXElement' && jsxHasNonEmptyTextContent(child)) {
      return true;
    }
  }

  return false;
}

/** Checks whether an opening element already exposes an accessible name. */
export function jsxHasAccessibleNameAttr(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  for (const attrName of ['aria-label', 'aria-labelledby', 'title']) {
    const value = getJsxStringAttr(opening, attrName);

    if (value === undefined) {
      continue;
    }

    if (value === '[expression]') {
      return true;
    }

    return value.trim().length > 0;
  }

  return false;
}

/** Checks whether an intrinsic element should participate in accessible-name checks. */
export function shouldCheckAccessibleName(
  opening: TSESTree.JSXOpeningElement,
  sourceText: string,
): boolean {
  const tag = getJsxTagName(opening.name, sourceText);

  if (!tag) {
    return false;
  }

  const lower = tag.toLowerCase();

  if (lower === 'input') {
    return getJsxStringAttr(opening, 'type')?.toLowerCase() !== 'hidden';
  }

  if (isNativeInteractiveElement(lower)) {
    return true;
  }

  const role = getJsxStringAttr(opening, 'role');

  return Boolean(role && INTERACTIVE_ROLES.has(role.toLowerCase()));
}

/** Checks whether an image should be treated as decorative. */
export function isDecorativeImage(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  const ariaHidden = getJsxBooleanAttr(opening, 'aria-hidden');
  const role = getJsxStringAttr(opening, 'role')?.toLowerCase();

  return ariaHidden === true || role === 'presentation' || role === 'none';
}

/** True when a semantic text or caption tag is assigned an interactive ARIA role. */
export function isSemanticElementWithInteractiveRole(
  lowerTagName: string,
  roleLower: string | undefined,
): boolean {
  return Boolean(
    roleLower &&
      INTERACTIVE_ROLES.has(roleLower) &&
      SEMANTIC_TAGS_DISCOURAGED_WITH_WIDGET_ROLE.has(lowerTagName),
  );
}
