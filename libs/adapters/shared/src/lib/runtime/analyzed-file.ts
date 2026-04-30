import type {
  AnalyzedFile,
  ObservedFact,
  ObservedNode,
} from '@critiq/core-rules-engine';
import { sortObservedNodes } from '@critiq/core-rules-engine';

import { createRangeFromOffsets } from './ranges';

function createRootNode(path: string, text: string): ObservedNode {
  const range = createRangeFromOffsets(text, 0, Math.max(text.length, 1));

  return {
    id: [
      'File',
      path,
      range.startLine,
      range.startColumn,
      range.endLine,
      range.endColumn,
    ].join(':'),
    kind: 'File',
    range,
    text,
    props: {
      text,
    },
  };
}

function factSortKey(fact: ObservedFact): string {
  return [
    String(fact.range.startLine).padStart(8, '0'),
    String(fact.range.startColumn).padStart(8, '0'),
    String(fact.range.endLine).padStart(8, '0'),
    String(fact.range.endColumn).padStart(8, '0'),
    fact.id,
  ].join(':');
}

export function buildAnalyzedFileWithFacts(
  path: string,
  language: string,
  text: string,
  facts: readonly ObservedFact[],
): AnalyzedFile {
  return {
    path,
    language,
    text,
    nodes: sortObservedNodes([createRootNode(path, text)]),
    semantics: {
      controlFlow: {
        functions: [],
        blocks: [],
        edges: [],
        facts: [...facts].sort((left, right) =>
          factSortKey(left).localeCompare(factSortKey(right)),
        ),
      },
    },
  };
}
