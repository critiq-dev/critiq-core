import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

export const JAVA_DOC_FACT_KINDS = {
  unmatchedParameterTag: 'java.doc.unmatched-parameter-tag',
  parameterTagNoDescription: 'java.doc.parameter-tag-no-description',
  emptyJavadocTag: 'java.doc.empty-javadoc-tag',
  malformedJavadocComment: 'java.doc.malformed-javadoc-comment',
} as const;

export interface CollectJavaDocFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectJavaDocFacts(
  options: CollectJavaDocFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectUnmatchedParamTagFacts(text, detector),
    ...collectParamTagNoDescriptionFacts(text, detector),
    ...collectEmptyJavadocTagFacts(text, detector),
    ...collectMalformedJavadocCommentFacts(text, detector),
  ];
}

const JAVADOC_BLOCK = /\/\*\*[\s\S]*?\*\//gu;

/**
 * JAVA-D1004: @param tags must reference declared method parameters.
 *
 * Multi-step analysis:
 * 1. Find all Javadoc blocks.
 * 2. For each block, extract @param tag names.
 * 3. Find the immediately following method/constructor signature.
 * 4. Parse actual parameter names from the signature.
 * 5. Emit a fact for each @param name that has no matching declared parameter.
 */
function collectUnmatchedParamTagFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_DOC_FACT_KINDS.unmatchedParameterTag;
  const findings: ObservedFact[] = [];

  for (const block of text.matchAll(JAVADOC_BLOCK)) {
    const blockStart = block.index ?? 0;
    const blockEnd = blockStart + block[0].length;
    const blockText = block[0];

    const paramNames: string[] = [];
    const paramTagPattern = /@param\s+(\S+)/gu;
    let paramMatch: RegExpExecArray | null;

    while ((paramMatch = paramTagPattern.exec(blockText)) !== null) {
      paramNames.push(paramMatch[1]);
    }

    if (paramNames.length === 0) continue;

    const signatureParams = findMethodParamsAfterBlock(text, blockEnd);

    if (signatureParams === null) continue;

    for (const paramName of paramNames) {
      if (!signatureParams.includes(paramName)) {
        const tagOffset = blockStart + blockText.indexOf(`@param ${paramName}`);
        const tagEnd = tagOffset + `@param ${paramName}`.length;

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: tagOffset,
            endOffset: tagEnd,
            text: `@param ${paramName}`,
          }),
        );
      }
    }
  }

  return findings;
}

function findMethodParamsAfterBlock(
  text: string,
  afterOffset: number,
): string[] | null {
  const rest = text.slice(afterOffset);
  const sigMatch = rest.match(
    /^\s*(?:\n\s*(?:\/\*[\s\S]*?\*\/\s*)*(?:@\w+(?:\([^)]*\))?\s*)*)*/u,
  );

  const afterAnnotations = afterOffset + (sigMatch ? sigMatch[0].length : 0);
  const methodRest = text.slice(afterAnnotations);

  const methodPattern =
    /(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\s+)*(?:<[^<>]*>\s+)?(?:\w+(?:\[\])*(?:\.\.\.)?\s+)*(\w+)\s*\(/u;

  const methodMatch = methodRest.match(methodPattern);

  if (!methodMatch) return null;

  const openParen = methodMatch.index! + methodMatch[0].length - 1;
  const closeParen = findParenClose(
    afterAnnotations + openParen - 1,
    text,
  );

  if (closeParen < 0) return null;

  const paramList = text.slice(
    afterAnnotations + openParen + 1,
    closeParen,
  );

  return extractJavaParamNames(paramList);
}

function findParenClose(openIndex: number, text: string): number {
  let depth = 0;
  let inString = false;
  let stringChar: string | null = null;

  for (let i = openIndex; i < text.length; i++) {
    const ch = text[i];

    if (inString) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === stringChar) {
        inString = false;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      inString = true;
      stringChar = ch;
      continue;
    }

    if (ch === '(') {
      depth++;
      continue;
    }

    if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }

    if (ch === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      if (nl < 0) return -1;
      i = nl;
      continue;
    }

    if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end < 0) return -1;
      i = end + 1;
      continue;
    }
  }

  return -1;
}

function extractJavaParamNames(paramList: string): string[] {
  const names: string[] = [];
  const params = splitParamListByComma(paramList);

  for (const param of params) {
    const name = extractNameFromParam(param);
    if (name) {
      names.push(name);
    }
  }

  return names;
}

function splitParamListByComma(paramList: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  let inString = false;
  let stringChar: string | null = null;

  for (const ch of paramList) {
    if (inString) {
      current += ch;
      if (ch === '\\') {
        continue;
      }
      if (ch === stringChar) {
        inString = false;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      inString = true;
      stringChar = ch;
      current += ch;
      continue;
    }

    if (ch === '<' || ch === '(') {
      depth++;
      current += ch;
      continue;
    }

    if (ch === '>' || ch === ')') {
      depth--;
      current += ch;
      continue;
    }

    if (ch === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  const last = current.trim();
  if (last) parts.push(last);

  return parts;
}

function extractNameFromParam(param: string): string | null {
  const cleaned = param.replace(/@\w+(?:\([^)]*\))?\s*/gu, '').trim();
  const parts = cleaned.split(/\s+/u);

  if (parts.length === 0) return null;

  let candidate = parts[parts.length - 1];

  if (candidate.endsWith('...')) {
    candidate = candidate.slice(0, -3);
  }

  if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/u.test(candidate)) {
    return candidate;
  }

  if (parts.length >= 2) {
    candidate = parts[parts.length - 2];
    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/u.test(candidate)) {
      return candidate;
    }
  }

  return null;
}

/**
 * JAVA-D1005: @param tags that have a name but no description.
 *
 * Also handles @return and @throws with no description.
 * Description = any non-whitespace text after the parameter/exception name
 * before the next tag, end of block, or newline within the Javadoc.
 */
function collectParamTagNoDescriptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_DOC_FACT_KINDS.parameterTagNoDescription;
  const findings: ObservedFact[] = [];

  for (const block of text.matchAll(JAVADOC_BLOCK)) {
    const blockStart = block.index ?? 0;
    const blockText = block[0];

    const patterns: RegExp[] = [
      /@param\s+(\S+)\s*(?=\n\s*\*\/|\n\s*\*\s*\n|\n\s*\*\s*(?:@\w|\*\/)|$)/gu,
      /@param\s+(\S+)\s+\n/gu,
      /@return\s*(?=\n\s*\*\/|\n\s*\*\s*\n|\n\s*\*\s*(?:@\w|\*\/)|$)/gu,
      /@return\s*\n/gu,
      /@throws\s+\S+\s*(?=\n\s*\*\/|\n\s*\*\s*\n|\n\s*\*\s*(?:@\w|\*\/)|$)/gu,
      /@throws\s+\S+\s*\n/gu,
    ];

    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.exec(blockText)) !== null) {
        const tagText = match[0].replace(/\s+$/u, '').trim();

        if (!tagText) continue;

        let startOffset = blockStart + match.index;

        if (/@return\s*$/u.test(tagText)) {
          startOffset = blockStart + match.index;
        }

        const endOffset = startOffset + tagText.length;

        if (tagText.startsWith('@return') && /@return\s*$/u.test(tagText)) {
          const isEmptyReturn = !blockText
            .slice(match.index + 7)
            .match(/^\s*\S/u);

          if (!isEmptyReturn) continue;
        }

        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset,
            endOffset,
            text: tagText,
          }),
        );
      }
    }
  }

  return dedupeFactsByOffset(findings);
}

/**
 * JAVA-D1006: Javadoc block tags with absolutely no content.
 *
 * Matches bare @param, @return, @throws, @see, @since, @deprecated,
 * @author, @version, @exception where the tag keyword is immediately
 * followed by nothing (end of block, newline, or another tag).
 */
function collectEmptyJavadocTagFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_DOC_FACT_KINDS.emptyJavadocTag,
    appliesTo: 'block',
    pattern:
      /@(?:param|return|throws|see|since|deprecated|author|version|exception)(?=\s*\*\/|\s*\n|\s*@)/gu,
  });
}

/**
 * JAVA-D1007: Malformed Javadoc comments with doubled @@ symbols.
 */
function collectMalformedJavadocCommentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_DOC_FACT_KINDS.malformedJavadocComment,
    appliesTo: 'block',
    pattern:
      /@@(?:param|return|throws|see|since|deprecated|author|version|exception)\b/gu,
  });
}

function dedupeFactsByOffset(facts: ObservedFact[]): ObservedFact[] {
  const seen = new Set<string>();
  return facts.filter((f) => {
    const key = `${f.kind}:${f.range.startLine}:${f.range.startColumn}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
