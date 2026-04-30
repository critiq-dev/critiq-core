import type { ObservedRange } from '@critiq/core-rules-engine';

import { findMatchingDelimiter } from './delimiters';
import { findAllMatches } from './matches';
import { createRangeFromOffsets } from './ranges';

export interface CallSnippet {
  calleeText: string;
  startOffset: number;
  endOffset: number;
  text: string;
  range: ObservedRange;
}

export function findCallSnippets(
  text: string,
  pattern: RegExp,
): CallSnippet[] {
  const snippets: CallSnippet[] = [];

  for (const match of findAllMatches(text, pattern)) {
    const openParenOffset = text.indexOf('(', match.startOffset);

    if (openParenOffset < 0 || openParenOffset >= match.endOffset) {
      continue;
    }

    const closeParenOffset = findMatchingDelimiter(
      text,
      openParenOffset,
      '(',
      ')',
    );

    if (closeParenOffset < 0) {
      continue;
    }

    const callText = text.slice(match.startOffset, closeParenOffset + 1);

    snippets.push({
      calleeText: callText.slice(0, callText.indexOf('(')).trim(),
      startOffset: match.startOffset,
      endOffset: closeParenOffset + 1,
      text: callText,
      range: createRangeFromOffsets(
        text,
        match.startOffset,
        closeParenOffset + 1,
      ),
    });
  }

  return snippets;
}
