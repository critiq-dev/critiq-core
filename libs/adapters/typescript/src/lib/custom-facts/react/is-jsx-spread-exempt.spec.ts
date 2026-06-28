import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isJsxSpreadExempt } from './is-jsx-spread-exempt';

function parseSpreadAttribute(source: string): TSESTree.JSXSpreadAttribute {
  const program = parse(source, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: false,
    range: false,
    tokens: false,
    sourceType: 'module',
  });

  function findSpread(node: unknown): TSESTree.JSXSpreadAttribute | null {
    if (typeof node !== 'object' || node === null) {
      return null;
    }

    const n = node as Record<string, unknown>;

    if (n['type'] === 'JSXSpreadAttribute') {
      return node as TSESTree.JSXSpreadAttribute;
    }

    for (const key of Object.keys(n)) {
      const val = n[key];
      if (val && typeof val === 'object') {
        if (Array.isArray(val)) {
          for (const item of val) {
            const result = findSpread(item);
            if (result) return result;
          }
        } else {
          const result = findSpread(val);
          if (result) return result;
        }
      }
    }
    return null;
  }

  const found = findSpread(program as unknown);
  if (!found) {
    throw new Error(`No JSXSpreadAttribute found in source: ${source}`);
  }
  return found;
}

describe('isJsxSpreadExempt', () => {
  it('exempts CallExpression spreads', () => {
    const attr = parseSpreadAttribute('<div {...getRootProps()} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('does not exempt unknown Identifier spreads', () => {
    const attr = parseSpreadAttribute('<div {...data} />');
    expect(isJsxSpreadExempt(attr)).toBe(false);
  });

  it('exempts react-hook-form field spread pattern', () => {
    const attr = parseSpreadAttribute('<input {...field} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('exempts react-hook-form form spread pattern', () => {
    const attr = parseSpreadAttribute('<Form {...form} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('exempts react-beautiful-dnd provided.droppableProps', () => {
    const attr = parseSpreadAttribute('<div {...provided.droppableProps} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('exempts react-beautiful-dnd provided.draggableProps', () => {
    const attr = parseSpreadAttribute('<div {...provided.draggableProps} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('exempts react-beautiful-dnd provided.dragHandleProps', () => {
    const attr = parseSpreadAttribute('<div {...provided.dragHandleProps} />');
    expect(isJsxSpreadExempt(attr)).toBe(true);
  });

  it('does not exempt MemberExpression with different object', () => {
    const attr = parseSpreadAttribute('<div {...other.droppableProps} />');
    expect(isJsxSpreadExempt(attr)).toBe(false);
  });

  it('does not exempt variable named other', () => {
    const attr = parseSpreadAttribute('<div {...other} />');
    expect(isJsxSpreadExempt(attr)).toBe(false);
  });

  it('does not exempt rest props spread', () => {
    const attr = parseSpreadAttribute('<div {...rest} />');
    expect(isJsxSpreadExempt(attr)).toBe(false);
  });
});
