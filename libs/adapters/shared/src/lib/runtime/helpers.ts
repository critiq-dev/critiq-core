import type {
  AnalyzedFile,
  ObservedFact,
  ObservedNode,
  ObservedRange,
} from '@critiq/core-rules-engine';
import { sortObservedNodes } from '@critiq/core-rules-engine';

export const SENSITIVE_LABEL_PATTERN =
  /\b(address|auth|body|card|cookie|credit|dob|email|jwt|pass(word)?|payload|phone|secret|session|ssn|token)\b/i;
export const CREDENTIAL_IDENTIFIER_PATTERN =
  /(password|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)/i;
export const REDACTION_WRAPPER_PATTERN =
  /\b(redact|mask|sanitize|anonymize|drop_sensitive|dropSensitive|omit_sensitive|omitSensitive|hash_sensitive|hashSensitive|safe_serialize|safeSerialize)\b/i;

export interface CallSnippet {
  calleeText: string;
  startOffset: number;
  endOffset: number;
  text: string;
  range: ObservedRange;
}

export interface CreateFactOptions {
  detector: string;
  appliesTo: ObservedFact['appliesTo'];
  kind: string;
  startOffset: number;
  endOffset: number;
  text: string;
  props?: Record<string, unknown>;
}

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

export function createObservedFactFromOffsets(
  text: string,
  options: CreateFactOptions,
): ObservedFact {
  const range = createRangeFromOffsets(
    text,
    options.startOffset,
    options.endOffset,
  );
  const id = [
    options.detector,
    options.kind,
    range.startLine,
    range.startColumn,
    range.endLine,
    range.endColumn,
  ].join(':');

  return {
    id,
    kind: options.kind,
    appliesTo: options.appliesTo,
    range,
    text: options.text,
    props: options.props ?? {},
  };
}

export function containsIdentifier(
  text: string,
  identifiers: ReadonlySet<string>,
): boolean {
  return [...identifiers].some((identifier) =>
    new RegExp(`\\b${escapeRegExp(identifier)}\\b`, 'u').test(text),
  );
}

export function findAllMatches(
  text: string,
  pattern: RegExp,
): Array<{ matchedText: string; startOffset: number; endOffset: number }> {
  const normalizedPattern = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
  const matches: Array<{
    matchedText: string;
    startOffset: number;
    endOffset: number;
  }> = [];

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

export function findMatchingDelimiter(
  text: string,
  openOffset: number,
  openDelimiter: string,
  closeDelimiter: string,
): number {
  let depth = 0;
  let quote: '"' | "'" | '`' | null = null;
  let escapeNext = false;

  for (let index = openOffset; index < text.length; index += 1) {
    const character = text[index];

    if (quote) {
      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (character === '\\' && quote !== '`') {
        escapeNext = true;
        continue;
      }

      if (character === quote) {
        quote = null;
      }

      continue;
    }

    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }

    if (character === openDelimiter) {
      depth += 1;
      continue;
    }

    if (character === closeDelimiter) {
      depth -= 1;

      if (depth === 0) {
        return index;
      }
    }
  }

  return -1;
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
