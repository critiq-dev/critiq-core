export interface CommentRange {
  startOffset: number;
  endOffset: number;
}

export function findSqlCommentRanges(text: string): CommentRange[] {
  const ranges: CommentRange[] = [];
  let i = 0;

  while (i < text.length - 1) {
    if (text[i] === '-' && text[i + 1] === '-') {
      const startOffset = i;
      const endOfLine = text.indexOf('\n', i);
      const endOffset = endOfLine === -1 ? text.length : endOfLine;
      ranges.push({ startOffset, endOffset });
      i = endOffset;
      continue;
    }

    if (text[i] === '/' && text[i + 1] === '*') {
      const startOffset = i;
      const endComment = text.indexOf('*/', i + 2);
      const endOffset = endComment === -1 ? text.length : endComment + 2;
      ranges.push({ startOffset, endOffset });
      i = endOffset;
      continue;
    }

    i++;
  }

  return ranges;
}

export function isInCommentRange(
  offset: number,
  commentRanges: CommentRange[],
): boolean {
  for (const range of commentRanges) {
    if (offset >= range.startOffset && offset < range.endOffset) {
      return true;
    }
  }

  return false;
}

export function stripSqlComments(text: string): string {
  const ranges = findSqlCommentRanges(text);
  if (ranges.length === 0) {
    return text;
  }
  const parts: string[] = [];
  let lastEnd = 0;
  for (const range of ranges) {
    parts.push(text.slice(lastEnd, range.startOffset));
    lastEnd = range.endOffset;
  }
  parts.push(text.slice(lastEnd));
  return parts.join('');
}
