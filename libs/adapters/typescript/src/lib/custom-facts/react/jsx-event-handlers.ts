import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { hasJsxAttribute } from './jsx-attributes';

const KEYBOARD_HANDLER_ATTRS = ['onKeyDown', 'onKeyPress', 'onKeyUp'];

const POINTER_OR_NON_CLICK_KEY_ATTRS = [
  'onMouseDown',
  'onMouseUp',
  'onPointerDown',
  'onPointerUp',
  'onKeyDown',
  'onKeyUp',
  'onKeyPress',
];

/** Checks whether an opening element binds a click handler. */
export function hasClickHandler(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  return hasJsxAttribute(opening, 'onClick');
}

/** Checks whether an opening element provides keyboard event handling. */
export function hasKeyboardHandler(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  return KEYBOARD_HANDLER_ATTRS.some((attrName) =>
    hasJsxAttribute(opening, attrName),
  );
}

/**
 * Non-click mouse, pointer, or key handlers on static-looking elements often
 * indicate a custom widget that still needs roles and focus management.
 */
export function hasPointerOrNonClickKeyHandler(
  opening: TSESTree.JSXOpeningElement,
): boolean {
  return POINTER_OR_NON_CLICK_KEY_ATTRS.some((attrName) =>
    hasJsxAttribute(opening, attrName),
  );
}
