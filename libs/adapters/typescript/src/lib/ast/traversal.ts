import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isNodeLike, type NodeLike } from './source-text';

function compareNodeLikes(left: NodeLike, right: NodeLike): number {
  if (left.range[0] !== right.range[0]) {
    return left.range[0] - right.range[0];
  }

  if (left.range[1] !== right.range[1]) {
    return left.range[1] - right.range[1];
  }

  return left.type.localeCompare(right.type);
}

export function isNode(value: unknown): value is TSESTree.Node {
  return (
    isNodeLike(value) &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

export function childNodesOf<TNode extends NodeLike>(node: TNode): TNode[] {
  const children: TNode[] = [];

  for (const [key, value] of Object.entries(node as unknown as Record<string, unknown>)) {
    if (key === 'loc' || key === 'range' || key === 'parent') {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNodeLike(entry)) {
          children.push(entry as TNode);
        }
      }

      continue;
    }

    if (isNodeLike(value)) {
      children.push(value as TNode);
    }
  }

  return children.sort(compareNodeLikes);
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
