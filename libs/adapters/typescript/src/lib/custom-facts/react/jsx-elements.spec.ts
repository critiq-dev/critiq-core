import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getJsxBooleanAttr,
  getJsxNumericAttr,
  getJsxStringAttr,
  hasJsxAttribute,
} from './jsx-attributes';
import {
  getJsxTagName,
  isDecorativeImage,
  isIntrinsicJsxTag,
  isNativeInteractiveElement,
  jsxHasAccessibleNameAttr,
  jsxHasNonEmptyTextContent,
} from './jsx-elements';

function getFirstJsxElement(sourceText: string): TSESTree.JSXElement {
  const program = parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  let found: TSESTree.JSXElement | undefined;

  const visit = (node: TSESTree.Node): void => {
    if (found) {
      return;
    }

    if (node.type === 'JSXElement') {
      found = node;
      return;
    }

    for (const value of Object.values(node)) {
      if (found || !value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (
            entry &&
            typeof entry === 'object' &&
            'type' in entry &&
            typeof entry.type === 'string'
          ) {
            visit(entry as TSESTree.Node);
          }
        }

        continue;
      }

      if (
        typeof value === 'object' &&
        'type' in value &&
        typeof value.type === 'string'
      ) {
        visit(value as TSESTree.Node);
      }
    }
  };

  visit(program as unknown as TSESTree.Node);

  if (!found) {
    throw new Error('Expected JSXElement in source');
  }

  return found;
}

describe('react JSX helpers', () => {
  it('reads intrinsic tags and static attributes', () => {
    const element = getFirstJsxElement(
      'export const x = <img alt="" aria-hidden={true} tabIndex={2} />;',
    );
    const opening = element.openingElement;

    expect(getJsxTagName(opening.name, '')).toBe('img');
    expect(getJsxStringAttr(opening, 'alt')).toBe('');
    expect(getJsxBooleanAttr(opening, 'aria-hidden')).toBe(true);
    expect(getJsxNumericAttr(opening, 'tabIndex')).toBe(2);
    expect(hasJsxAttribute(opening, 'tabIndex')).toBe(true);
    expect(isDecorativeImage(opening)).toBe(true);
  });

  it('understands text content and intrinsic interactivity', () => {
    const buttonElement = getFirstJsxElement(
      'export const x = <button type="button">Save</button>;',
    );

    expect(jsxHasAccessibleNameAttr(buttonElement.openingElement)).toBe(false);
    expect(jsxHasNonEmptyTextContent(buttonElement)).toBe(true);
    expect(isNativeInteractiveElement('button')).toBe(true);
    expect(isIntrinsicJsxTag('button')).toBe(true);
    expect(isIntrinsicJsxTag('MyButton')).toBe(false);
  });
});
