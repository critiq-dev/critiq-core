import type { ObservedRange } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

export interface NodeLike {
  type: string;
  loc: {
    start: {
      line: number;
      column: number;
    };
    end: {
      line: number;
      column: number;
    };
  };
  range: [number, number];
}

export function isNodeLike(value: unknown): value is NodeLike {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    typeof (value as { type?: unknown }).type === 'string' &&
    Array.isArray((value as { range?: unknown }).range) &&
    Boolean((value as { loc?: unknown }).loc)
  );
}

export function toObservedRange(node: NodeLike): ObservedRange {
  return {
    startLine: node.loc.start.line,
    startColumn: node.loc.start.column + 1,
    endLine: node.loc.end.line,
    endColumn: node.loc.end.column + 1,
  };
}

export function excerptFor(node: NodeLike, sourceText: string): string {
  return sourceText.slice(node.range[0], node.range[1]);
}

export function getNodeText(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'PrivateIdentifier') {
    return `#${node.name}`;
  }

  return excerptFor(node, sourceText);
}

export function getCalleeText(
  callee: TSESTree.CallExpression['callee'],
  sourceText: string,
): string | undefined {
  if (callee.type === 'Identifier') {
    return callee.name;
  }

  if (callee.type === 'MemberExpression') {
    const objectText = getNodeText(callee.object, sourceText);
    const propertyText = getNodeText(callee.property, sourceText);

    if (objectText && propertyText) {
      return `${objectText}.${propertyText}`;
    }
  }

  return getNodeText(callee, sourceText);
}

export function getStringLiteralValue(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
): string | undefined {
  if (!node || node.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  return node.value;
}

export function getNumericLiteralValue(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
): number | undefined {
  if (!node || node.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (node.type === 'Literal' && typeof node.value === 'number') {
    return node.value;
  }

  if (node.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  const literal = node.value.trim();

  if (/^0o[0-7]+$/iu.test(literal)) {
    return Number.parseInt(literal.slice(2), 8);
  }

  if (/^0x[0-9a-f]+$/iu.test(literal)) {
    return Number.parseInt(literal.slice(2), 16);
  }

  if (/^0b[01]+$/iu.test(literal)) {
    return Number.parseInt(literal.slice(2), 2);
  }

  if (/^0[0-7]+$/u.test(literal)) {
    return Number.parseInt(literal, 8);
  }

  if (/^-?\d+(?:\.\d+)?$/u.test(literal)) {
    return Number(literal);
  }

  return undefined;
}

export function normalizeText(text: string | undefined): string {
  return text?.replace(/\s+/gu, ' ').trim() ?? '';
}
