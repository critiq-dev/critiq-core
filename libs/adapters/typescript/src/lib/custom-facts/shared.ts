import type { ObservedFact, ObservedRange } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isSensitiveIdentifierText,
  tokenizeIdentifierLikeText,
} from '../auth-vocabulary';

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

export type FunctionLikeNode =
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression;

const compatibilityMarkerPattern =
  /\b(?:compat(?:ibility)?|interop|legacy|migration)\b/i;

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

export function walkAstWithAncestors(
  node: TSESTree.Node,
  visitor: (node: TSESTree.Node, ancestors: readonly TSESTree.Node[]) => void,
  ancestors: readonly TSESTree.Node[] = [],
): void {
  visitor(node, ancestors);

  for (const value of Object.values(node)) {
    if (!value) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNode(entry)) {
          walkAstWithAncestors(entry, visitor, [...ancestors, node]);
        }
      }

      continue;
    }

    if (isNode(value)) {
      walkAstWithAncestors(value, visitor, [...ancestors, node]);
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

export function collectObjectBindings(
  context: TypeScriptFactDetectorContext,
): Map<string, TSESTree.ObjectExpression> {
  const bindings = new Map<string, TSESTree.ObjectExpression>();

  walkAst(context.program, (node) => {
    if (node.type !== 'VariableDeclarator') {
      return;
    }

    if (node.id.type !== 'Identifier') {
      return;
    }

    if (!node.init || node.init.type !== 'ObjectExpression') {
      return;
    }

    bindings.set(node.id.name, node.init);
  });

  return bindings;
}

export function resolveObjectExpression(
  expression:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  bindings: ReadonlyMap<string, TSESTree.ObjectExpression>,
): TSESTree.ObjectExpression | undefined {
  if (!expression || expression.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (expression.type === 'ObjectExpression') {
    return expression;
  }

  if (expression.type === 'Identifier') {
    return bindings.get(expression.name);
  }

  return undefined;
}

export function isFunctionLike(
  node: TSESTree.Node | null | undefined,
): node is FunctionLikeNode {
  return Boolean(
    node &&
      (node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression'),
  );
}

export function walkFunctionBodySkippingNestedFunctions(
  root: FunctionLikeNode,
  visitor: (node: TSESTree.Node) => void,
): void {
  const visit = (node: TSESTree.Node): void => {
    if (isFunctionLike(node) && node !== root) {
      return;
    }

    visitor(node);

    for (const value of Object.values(node)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (isNode(entry)) {
            visit(entry);
          }
        }

        continue;
      }

      if (isNode(value)) {
        visit(value);
      }
    }
  };

  if (root.body.type === 'BlockStatement') {
    for (const statement of root.body.body) {
      visit(statement);
    }

    return;
  }

  visit(root.body);
}

export function isCompatibilityMarkerText(
  text: string | undefined,
): boolean {
  return (
    typeof text === 'string' &&
    (compatibilityMarkerPattern.test(text) ||
      tokenizeIdentifierLikeText(text).some((token) =>
        ['compat', 'compatibility', 'interop', 'legacy', 'migration'].includes(
          token,
        ),
      ))
  );
}

function collectNamedCompatibilityTexts(
  ancestors: readonly TSESTree.Node[],
  sourceText: string,
): string[] {
  const texts: string[] = [];

  for (const ancestor of ancestors) {
    if (ancestor.type === 'FunctionDeclaration' && ancestor.id) {
      texts.push(ancestor.id.name);
      continue;
    }

    if (
      ancestor.type === 'VariableDeclarator' &&
      ancestor.id.type === 'Identifier' &&
      isFunctionLike(ancestor.init)
    ) {
      texts.push(ancestor.id.name);
      continue;
    }

    if (
      ancestor.type === 'Property' &&
      isFunctionLike(ancestor.value)
    ) {
      texts.push(getNodeText(ancestor.key, sourceText) ?? '');
    }
  }

  return texts;
}

function getProgramComments(
  program: TSESTree.Program,
): readonly TSESTree.Comment[] {
  return (program as TSESTree.Program & { comments?: TSESTree.Comment[] })
    .comments ?? [];
}

export function hasCompatibilityMarkerNearNode(options: {
  ancestors?: readonly TSESTree.Node[];
  node: TSESTree.Node;
  program: TSESTree.Program;
  sourceText: string;
}): boolean {
  const { ancestors = [], node, program, sourceText } = options;

  if (isCompatibilityMarkerText(getNodeText(node, sourceText))) {
    return true;
  }

  if (
    collectNamedCompatibilityTexts(ancestors, sourceText).some(
      isCompatibilityMarkerText,
    )
  ) {
    return true;
  }

  const comments = getProgramComments(program);
  const nodeStartOffset = node.range[0];
  const nodeEndOffset = node.range[1];
  const nodeStartLine = node.loc.start.line;
  const nodeEndLine = node.loc.end.line;

  return comments.some((comment) => {
    if (!isCompatibilityMarkerText(comment.value)) {
      return false;
    }

    if (
      comment.loc.start.line <= nodeEndLine + 1 &&
      comment.loc.end.line >= nodeStartLine - 2
    ) {
      return true;
    }

    if (comment.range[1] <= nodeStartOffset) {
      return nodeStartOffset - comment.range[1] <= 160;
    }

    if (comment.range[0] >= nodeStartOffset) {
      return comment.range[0] - nodeEndOffset <= 80;
    }

    return false;
  });
}

export function looksSensitiveIdentifier(text: string | undefined): boolean {
  return isSensitiveIdentifierText(text);
}
