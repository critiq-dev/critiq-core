import type { ObservedRange } from '@critiq/core-rules-engine';

function buildLineStarts(text: string): number[] {
  const lineStarts = [0];

  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      lineStarts.push(index + 1);
    }
  }

  return lineStarts;
}

function offsetToLineColumn(
  lineStarts: readonly number[],
  offset: number,
): { line: number; column: number } {
  let low = 0;
  let high = lineStarts.length - 1;

  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const lineStart = lineStarts[middle];
    const nextLineStart =
      middle + 1 < lineStarts.length
        ? lineStarts[middle + 1]
        : Number.MAX_SAFE_INTEGER;

    if (offset < lineStart) {
      high = middle - 1;
      continue;
    }

    if (offset >= nextLineStart) {
      low = middle + 1;
      continue;
    }

    return {
      line: middle + 1,
      column: offset - lineStart + 1,
    };
  }

  return {
    line: 1,
    column: 1,
  };
}

export function createRangeFromOffsets(
  text: string,
  startOffset: number,
  endOffset: number,
): ObservedRange {
  const lineStarts = buildLineStarts(text);
  const safeEndOffset = Math.max(startOffset + 1, endOffset);
  const start = offsetToLineColumn(lineStarts, startOffset);
  const end = offsetToLineColumn(lineStarts, safeEndOffset);

  return {
    startLine: start.line,
    startColumn: start.column,
    endLine: end.line,
    endColumn: end.column,
  };
}
