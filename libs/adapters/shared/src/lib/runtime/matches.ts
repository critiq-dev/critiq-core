export interface TextMatch {
  matchedText: string;
  startOffset: number;
  endOffset: number;
}

export function findAllMatches(
  text: string,
  pattern: RegExp,
): TextMatch[] {
  const normalizedPattern = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
  const matches: TextMatch[] = [];

  for (const match of text.matchAll(normalizedPattern)) {
    const matchedText = match[0];
    const startOffset = match.index ?? 0;

    matches.push({
      matchedText,
      startOffset,
      endOffset: startOffset + matchedText.length,
    });
  }

  return matches;
}
