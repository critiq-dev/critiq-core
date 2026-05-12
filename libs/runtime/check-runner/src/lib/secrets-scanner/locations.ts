export function lineColumnFromOffset(
  text: string,
  startOffset: number,
  endOffset: number,
): {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
} {
  let line = 1;
  let column = 1;
  let i = 0;
  let startLine = 1;
  let startColumn = 1;
  let endLine = 1;
  let endColumn = 1;

  while (i < text.length && i < startOffset) {
    if (text[i] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }

    i += 1;
  }

  startLine = line;
  startColumn = column;

  while (i < text.length && i < endOffset) {
    if (text[i] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }

    i += 1;
  }

  endLine = line;
  endColumn = column;

  return { startLine, startColumn, endLine, endColumn };
}
