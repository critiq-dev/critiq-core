import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { hasJsxAttribute } from './jsx-attributes';

const KEYBOARD_HANDLER_ATTRS = ['onKeyDown', 'onKeyPress', 'onKeyUp'];

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
