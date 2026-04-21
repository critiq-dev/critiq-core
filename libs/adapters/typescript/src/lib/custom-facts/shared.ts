import type { ObservedFact, ObservedRange } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

interface NodeLike {
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

export interface TypeScriptFactDetectorContext {
  nodeIds: WeakMap<object, string>;
  path: string;
  program: TSESTree.Program;
  sourceText: string;
}

export interface CreateObservedFactOptions {
  appliesTo: ObservedFact['appliesTo'];
  kind: string;
  node: TSESTree.Node;
  nodeIds: WeakMap<object, string>;
  props?: Record<string, unknown>;
  text?: string;
}

export type TypeScriptFactDetector = (
  context: TypeScriptFactDetectorContext,
) => ObservedFact[];

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

export function createObservedFact(
  options: CreateObservedFactOptions,
): ObservedFact {
  const range = toObservedRange(options.node);
  const primaryNodeId = options.nodeIds.get(options.node as object);
  const id = [
    'ts-detector',
    options.kind,
    range.startLine,
    range.startColumn,
    range.endLine,
    range.endColumn,
    primaryNodeId ?? 'node',
  ].join(':');

  return {
    id,
    kind: options.kind,
    appliesTo: options.appliesTo,
    primaryNodeId,
    range,
    text: options.text,
    props: options.props ?? {},
  };
}

export function walkAst(
  node: TSESTree.Node,
  visitor: (node: TSESTree.Node) => void,
): void {
  visitor(node);

  for (const value of Object.values(node)) {
    if (!value) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNode(entry)) {
          walkAst(entry, visitor);
        }
      }

      continue;
    }

    if (isNode(value)) {
      walkAst(value, visitor);
    }
  }
}

export function isNode(value: unknown): value is TSESTree.Node {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    typeof (value as { type?: unknown }).type === 'string' &&
    Array.isArray((value as { range?: unknown }).range) &&
    Boolean((value as { loc?: unknown }).loc)
  );
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

export function isBooleanLiteral(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  value: boolean,
): boolean {
  return node?.type === 'Literal' && node.value === value;
}

export function isIdentifierNamed(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  name: string,
): boolean {
  return node?.type === 'Identifier' && node.name === name;
}

export function isPropertyNamed(
  property:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.Property['key']
    | null
    | undefined,
  name: string,
): boolean {
  if (!property) {
    return false;
  }

  if (property.type === 'Identifier') {
    return property.name === name;
  }

  return property.type === 'Literal' && property.value === name;
}

export function getObjectProperty(
  objectExpression: TSESTree.ObjectExpression | null | undefined,
  name: string,
): TSESTree.Property | undefined {
  if (!objectExpression) {
    return undefined;
  }

  return objectExpression.properties.find(
    (property): property is TSESTree.Property =>
      property.type === 'Property' && isPropertyNamed(property.key, name),
  );
}

export function looksSensitiveIdentifier(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  return /\b(address|auth|card|cookie|credit|dob|email|jwt|pass(word)?|phone|secret|session|ssn|token)\b/i.test(
    text,
  );
}

