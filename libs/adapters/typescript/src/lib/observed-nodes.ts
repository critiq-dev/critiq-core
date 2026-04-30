import type { ObservedNode } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  childNodesOf,
  excerptFor,
  toObservedRange,
  type NodeLike,
} from './ast';

type JsonLike =
  | string
  | number
  | boolean
  | null
  | JsonLike[]
  | { [key: string]: JsonLike };

function projectLiteralValue(node: TSESTree.Literal): string {
  if (typeof node.raw === 'string' && node.raw.length > 0) {
    return node.raw;
  }

  return String(node.value);
}

function isExpressionNode(value: unknown): value is TSESTree.Expression {
  return value !== null && typeof value === 'object' && 'type' in value;
}

function firstExpressionArgument(
  node: TSESTree.CallExpression,
): TSESTree.Expression | undefined {
  const [firstArgument] = node.arguments;

  return isExpressionNode(firstArgument) ? firstArgument : undefined;
}

function projectCallArgument(
  argument: TSESTree.CallExpressionArgument,
  sourceText: string,
): JsonLike {
  if (isExpressionNode(argument)) {
    return projectExpression(argument, sourceText);
  }

  return {
    text: excerptFor(argument, sourceText),
  };
}

function projectExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): JsonLike {
  if (!node) {
    return null;
  }

  switch (node.type) {
    case 'Identifier':
      return { text: node.name };
    case 'PrivateIdentifier':
      return { text: `#${node.name}` };
    case 'Literal':
      return { text: projectLiteralValue(node) };
    case 'TemplateLiteral':
      return { text: excerptFor(node, sourceText) };
    case 'CallExpression':
      return {
        text: excerptFor(node, sourceText),
        callee: projectExpression(node.callee as TSESTree.Expression, sourceText),
        argument: projectExpression(firstExpressionArgument(node), sourceText),
      };
    case 'MemberExpression':
      return {
        text: excerptFor(node, sourceText),
        object: projectExpression(node.object, sourceText),
        property: projectExpression(node.property, sourceText),
      };
    default:
      return {
        text: excerptFor(node, sourceText),
      };
  }
}

function projectProps(
  node: TSESTree.Node,
  sourceText: string,
): Record<string, JsonLike> {
  const base = {
    text: excerptFor(node, sourceText),
  } satisfies Record<string, JsonLike>;

  switch (node.type) {
    case 'Identifier':
      return {
        ...base,
        text: node.name,
      };
    case 'Literal':
      return {
        ...base,
        text: projectLiteralValue(node),
      };
    case 'CallExpression':
      return {
        ...base,
        callee: projectExpression(node.callee as TSESTree.Expression, sourceText),
        argument: projectExpression(firstExpressionArgument(node), sourceText),
        arguments: node.arguments.map((argument) =>
          projectCallArgument(argument, sourceText),
        ),
      };
    case 'MemberExpression':
      return {
        ...base,
        object: projectExpression(node.object, sourceText),
        property: projectExpression(node.property, sourceText),
      };
    default:
      return base;
  }
}

function buildNodeId(node: NodeLike & { type: string }, index: number): string {
  return [
    node.type,
    String(node.loc.start.line).padStart(6, '0'),
    String(node.loc.start.column + 1).padStart(6, '0'),
    String(node.loc.end.line).padStart(6, '0'),
    String(node.loc.end.column + 1).padStart(6, '0'),
    String(index).padStart(6, '0'),
  ].join(':');
}

function visitNode(
  node: NodeLike & { type: string },
  sourceText: string,
  nodes: ObservedNode[],
  nodeIds: WeakMap<object, string>,
  parentId?: string,
): string {
  const index = nodes.length;
  const nodeId = buildNodeId(node, index);
  const observedNode: ObservedNode = {
    id: nodeId,
    kind: node.type,
    range: toObservedRange(node),
    text: excerptFor(node, sourceText),
    parentId,
    props: projectProps(node as TSESTree.Node, sourceText),
  };

  nodes.push(observedNode);
  nodeIds.set(node as unknown as object, nodeId);

  const childIds = childNodesOf(node).map((child) =>
    visitNode(
      child as NodeLike & { type: string },
      sourceText,
      nodes,
      nodeIds,
      nodeId,
    ),
  );

  if (childIds.length > 0) {
    observedNode.childrenIds = childIds;
  }

  return nodeId;
}

export function buildObservedNodes(
  program: TSESTree.Program,
  sourceText: string,
): { nodeIds: WeakMap<object, string>; nodes: ObservedNode[] } {
  const nodeIds = new WeakMap<object, string>();
  const nodes: ObservedNode[] = [];

  visitNode(program as NodeLike & { type: string }, sourceText, nodes, nodeIds);

  return {
    nodeIds,
    nodes,
  };
}
