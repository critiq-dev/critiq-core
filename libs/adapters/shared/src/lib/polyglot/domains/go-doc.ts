import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact } from '../fact-utils';

export const GO_DOC_FACT_KINDS = {
  malformedDeprecatedComment: 'go.doc.malformed-deprecated-comment',
} as const;

export interface CollectGoDocFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectGoDocFacts(
  options: CollectGoDocFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMalformedDeprecatedCommentFacts(text, detector),
  ];
}

const BACKTICK = '`';

/**
 * Detects malformed "deprecated" doc comments in Go source.
 *
 * Go convention requires `// Deprecated: explanation` (capital D, colon after
 * Deprecated). Any comment line that mentions "deprecated" but does not follow
 * this format is flagged.
 *
 * String literal and backtick literal contents are stripped before matching to
 * avoid false positives inside strings.
 *
 * V1 scope: line comments only. Block comments are not detected.
 */
function collectMalformedDeprecatedCommentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_DOC_FACT_KINDS.malformedDeprecatedComment;
  const findings: ObservedFact[] = [];

  const cleanedText = replaceStringContents(text);

  const pattern = /\/\/\s*[Dd]eprecated(?!:)/gu;

  for (const match of findAllMatches(cleanedText, pattern)) {
    const matchedText = text.slice(match.startOffset, match.endOffset);

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: matchedText,
      }),
    );
  }

  return findings;
}

function replaceStringContents(source: string): string {
  const doubleQuoted = /"([^"\\]*(?:\\.[^"\\]*)*)"/gu;
  const backtickQuoted = new RegExp(BACKTICK + '[^' + BACKTICK + ']*' + BACKTICK, 'gu');

  return source
    .replace(doubleQuoted, (match) =>
      match[0] + match.slice(1, -1).replace(/[^\n]/gu, ' ') + '"',
    )
    .replace(backtickQuoted, (match) =>
      BACKTICK + match.slice(1, -1).replace(/[^\n]/gu, ' ') + BACKTICK,
    );
}
