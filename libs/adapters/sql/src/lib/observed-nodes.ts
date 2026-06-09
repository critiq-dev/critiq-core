import type { ObservedNode } from '@critiq/core-rules-engine';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import type { AST } from 'node-sql-parser';

function toObservedRange(startLine: number, startCol: number, endLine: number, endCol: number) {
  return {
    startLine,
    startColumn: startCol,
    endLine,
    endColumn: endCol,
  };
}

function buildNodeId(kind: string, index: number): string {
  return `sql-node:${kind}:${String(index).padStart(6, '0')}`;
}

export function buildObservedNodes(
  _ast: AST | AST[],
  _sourceText: string,
): { nodes: ObservedNode[] } {
  return { nodes: [] };
}
