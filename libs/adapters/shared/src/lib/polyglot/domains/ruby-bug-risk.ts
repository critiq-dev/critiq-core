import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { stripHashLineComment } from '../text';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const RUBY_BUG_RISK_FACT_KINDS = {
  exceptionClassOverwritten: 'ruby.bug-risk.exception-class-overwritten',
  rawSqlWithoutSquish: 'ruby.bug-risk.raw-sql-without-squish',
  divisionByZero: 'ruby.bug-risk.division-by-zero',
  assignmentInCondition: 'ruby.bug-risk.assignment-in-condition',
  duplicateHashKeys: 'ruby.bug-risk.duplicate-hash-keys',
  deprecatedUriEscape: 'ruby.bug-risk.deprecated-uri-escape',
  deprecatedUriRegexp: 'ruby.bug-risk.deprecated-uri-regexp',
  deprecatedOpensslApi: 'ruby.bug-risk.deprecated-openssl-api',
  rescueException: 'ruby.bug-risk.rescue-exception',
  errorInheritsException: 'ruby.bug-risk.error-inherits-exception',
  duplicateConstantAssignment:
    'ruby.bug-risk.duplicate-constant-assignment',
  ioSelectSingleArg: 'ruby.bug-risk.io-select-single-arg',
  badOperandOrder: 'ruby.bug-risk.bad-operand-order',
  gitInGemspec: 'ruby.bug-risk.git-in-gemspec',
  ignoredColumnAccessed: 'ruby.bug-risk.ignored-column-accessed',
  renamedColumnAccessed: 'ruby.bug-risk.renamed-column-accessed',
  deprecatedBigDecimalNew: 'ruby.bug-risk.deprecated-big-decimal-new',
  symbolBooleanName: 'ruby.bug-risk.symbol-boolean-name',
  circularArgumentReference: 'ruby.bug-risk.circular-argument-reference',
  deprecatedClassMethods: 'ruby.bug-risk.deprecated-class-methods',
  disjunctiveAssignmentInConstructor:
    'ruby.bug-risk.disjunctive-assignment-in-constructor',
  duplicateCaseConditions:
    'ruby.bug-risk.duplicate-case-conditions',
  duplicateMethodDefinitions:
    'ruby.bug-risk.duplicate-method-definitions',
  eachWithObjectImmutableArg:
    'ruby.bug-risk.each-with-object-immutable-arg',
  elseFollowedByExpression:
    'ruby.bug-risk.else-followed-by-expression',
  emptyEnsureBlock:
    'ruby.bug-risk.empty-ensure-block',
  emptyExpression:
    'ruby.bug-risk.empty-expression',
  emptyInterpolation:
    'ruby.bug-risk.empty-interpolation',
  whenBranchWithoutBody:
    'ruby.bug-risk.when-branch-without-body',
  endInMethod:
    'ruby.bug-risk.end-in-method',
  returnInEnsure:
    'ruby.bug-risk.return-in-ensure',
  flipFlopOperator:
    'ruby.bug-risk.flip-flop-operator',
  heredocMethodOrder:
    'ruby.bug-risk.heredoc-method-order',
  unintendedStringConcatenation:
    'ruby.bug-risk.unintended-string-concatenation',
  ineffectiveAccessModifier:
    'ruby.bug-risk.ineffective-access-modifier',
  interpolationInSingleQuote:
    'ruby.bug-risk.interpolation-in-single-quote',
  nonLocalExitFromIterator:
    'ruby.bug-risk.non-local-exit-from-iterator',
  unsafeNumberConversion:
    'ruby.bug-risk.unsafe-number-conversion',
  badMagicCommentOrder:
    'ruby.bug-risk.bad-magic-comment-order',
  groupedParenthesesInCall:
    'ruby.bug-risk.grouped-parentheses-in-call',
  invalidPercentStringLiteral:
    'ruby.bug-risk.invalid-percent-string-literal',
  invalidPercentSymbolArray:
    'ruby.bug-risk.invalid-percent-symbol-array',
  unnecessaryRequire:
    'ruby.bug-risk.unnecessary-require',
  unnecessarySplat:
    'ruby.bug-risk.unnecessary-splat',
  withIndexValueUnused:
    'ruby.bug-risk.with-index-value-unused',
  withObjectValueUnused:
    'ruby.bug-risk.with-object-value-unused',
  regexLiteralInCondition:
    'ruby.bug-risk.regex-literal-in-condition',
  predicateMethodWithoutParentheses:
    'ruby.bug-risk.predicate-method-without-parentheses',
  invalidRescueType:
    'ruby.bug-risk.invalid-rescue-type',
  unsafeSafeNavigationChain:
    'ruby.bug-risk.unsafe-safe-navigation-chain',
  inconsistentSafeNavigation:
    'ruby.bug-risk.inconsistent-safe-navigation',
  safeNavigationWithEmpty:
    'ruby.bug-risk.safe-navigation-with-empty',
  argumentOverwrittenBeforeUse:
    'ruby.bug-risk.argument-overwritten-before-use',
  badRescueOrdering:
    'ruby.bug-risk.bad-rescue-ordering',
  outerVariableShadowed:
    'ruby.bug-risk.outer-variable-shadowed',
  suppressedExceptions:
    'ruby.bug-risk.suppressed-exceptions',
  toJsonWithoutArgument:
    'ruby.bug-risk.to-json-without-argument',
  unreachableCode:
    'ruby.bug-risk.unreachable-code',
  unusedMethodArguments:
    'ruby.bug-risk.unused-method-arguments',
  uselessAccessModifier:
    'ruby.bug-risk.useless-access-modifier',
} as const;

const RESCUE_EXCEPTION_CLASS_NAMES =
  'StandardError|Exception|RuntimeError|ArgumentError|NameError|TypeError|NoMethodError|IOError|IndexError|RangeError|RegexpError|SyntaxError|LoadError|ZeroDivisionError|NotImplementedError|ScriptError|SecurityError|SystemCallError|SystemStackError|ThreadError|FrozenError|LocalJumpError';

export interface CollectRubyBugRiskFactsOptions {
  text: string;
  detector: string;
}

export function collectRubyBugRiskFacts(
  options: CollectRubyBugRiskFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectExceptionClassOverwrittenFacts(text, detector),
    ...collectRawSqlWithoutSquishFacts(text, detector),
    ...collectDivisionByZeroFacts(text, detector),
    ...collectAssignmentInConditionFacts(text, detector),
    ...collectDuplicateHashKeyFacts(text, detector),
    ...collectDeprecatedUriEscapeFacts(text, detector),
    ...collectDeprecatedUriRegexpFacts(text, detector),
    ...collectDeprecatedOpensslApiFacts(text, detector),
    ...collectRescueExceptionFacts(text, detector),
    ...collectErrorInheritsExceptionFacts(text, detector),
    ...collectDuplicateConstantAssignmentFacts(text, detector),
    ...collectIoSelectSingleArgFacts(text, detector),
    ...collectBadOperandOrderFacts(text, detector),
    ...collectGitInGemspecFacts(text, detector),
    ...collectIgnoredColumnAccessedFacts(text, detector),
    ...collectRenamedColumnAccessedFacts(text, detector),
    ...collectDeprecatedBigDecimalNewFacts(text, detector),
    ...collectSymbolBooleanNameFacts(text, detector),
    ...collectCircularArgumentReferenceFacts(text, detector),
    ...collectDeprecatedClassMethodsFacts(text, detector),
    ...collectDisjunctiveAssignmentInConstructorFacts(text, detector),
    ...collectDuplicateCaseConditionsFacts(text, detector),
    ...collectDuplicateMethodDefinitionsFacts(text, detector),
    ...collectEachWithObjectImmutableArgFacts(text, detector),
    ...collectElseFollowedByExpressionFacts(text, detector),
    ...collectEmptyEnsureBlockFacts(text, detector),
    ...collectEmptyExpressionFacts(text, detector),
    ...collectEmptyInterpolationFacts(text, detector),
    ...collectWhenBranchWithoutBodyFacts(text, detector),
    ...collectEndInMethodFacts(text, detector),
    ...collectReturnInEnsureFacts(text, detector),
    ...collectFlipFlopOperatorFacts(text, detector),
    ...collectHeredocMethodOrderFacts(text, detector),
    ...collectUnintendedStringConcatenationFacts(text, detector),
    ...collectIneffectiveAccessModifierFacts(text, detector),
    ...collectInterpolationInSingleQuoteFacts(text, detector),
    ...collectNonLocalExitFromIteratorFacts(text, detector),
    ...collectUnsafeNumberConversionFacts(text, detector),
    ...collectBadMagicCommentOrderFacts(text, detector),
    ...collectGroupedParenthesesInCallFacts(text, detector),
    ...collectInvalidPercentStringLiteralFacts(text, detector),
    ...collectInvalidPercentSymbolArrayFacts(text, detector),
    ...collectUnnecessaryRequireFacts(text, detector),
    ...collectUnnecessarySplatFacts(text, detector),
    ...collectWithIndexValueUnusedFacts(text, detector),
    ...collectWithObjectValueUnusedFacts(text, detector),
    ...collectRegexLiteralInConditionFacts(text, detector),
    ...collectPredicateMethodWithoutParenthesesFacts(text, detector),
    ...collectInvalidRescueTypeFacts(text, detector),
    ...collectUnsafeSafeNavigationChainFacts(text, detector),
    ...collectInconsistentSafeNavigationFacts(text, detector),
    ...collectSafeNavigationWithEmptyFacts(text, detector),
    ...collectArgumentOverwrittenBeforeUseFacts(text, detector),
    ...collectBadRescueOrderingFacts(text, detector),
    ...collectOuterVariableShadowedFacts(text, detector),
    ...collectSuppressedExceptionsFacts(text, detector),
    ...collectToJsonWithoutArgumentFacts(text, detector),
    ...collectUnreachableCodeFacts(text, detector),
    ...collectUnusedMethodArgumentsFacts(text, detector),
    ...collectUselessAccessModifierFacts(text, detector),
  ]);
}

function collectExceptionClassOverwrittenFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.exceptionClassOverwritten,
    appliesTo: 'block',
    pattern: new RegExp(
      `\\brescue\\s*=>\\s*(?:${RESCUE_EXCEPTION_CLASS_NAMES})\\b`,
      'g',
    ),
  });
}

function collectRawSqlWithoutSquishFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.rawSqlWithoutSquish;
  const callPatterns = [/\bwhere\s*\(/g, /\bfind_by_sql\s*\(/g];

  return callPatterns.flatMap((pattern) =>
    collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern,
      state: undefined,
      predicate: (snippet) => {
        if (!/<<-?~?\w*/u.test(snippet.text)) {
          return false;
        }

        return !/\.squish\b/u.test(snippet.text);
      },
    }),
  );
}

function collectDivisionByZeroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.divisionByZero;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\/\s*0(?:\.0+)?\b/g;

    for (const match of findAllMatches(stripped, pattern)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + match.startOffset,
          endOffset: offset + match.endOffset,
          text: match.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectAssignmentInConditionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.assignmentInCondition;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:if|unless|while|until)\s+(?:\([^)]*\s*)?(\w+)\s*=(?!=)(?![=>])/g,
  });
}

function collectDeprecatedUriEscapeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedUriEscape,
    appliesTo: 'block',
    pattern: /\bURI\.(?:escape|unescape|encode|decode)\s*\(/g,
  });
}

function collectDeprecatedUriRegexpFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedUriRegexp,
    appliesTo: 'block',
    pattern: /\bURI\.regexp\b/g,
  });
}

function collectDeprecatedOpensslApiFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.deprecatedOpensslApi;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bOpenSSL::Cipher::\w+\.new\s*\(/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bOpenSSL::Digest::\w+\.(?:digest|new)\s*\(/g,
    }),
  );
}

function collectRescueExceptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.rescueException,
    appliesTo: 'block',
    pattern: /\brescue\s+(?:::)?Exception\b/g,
  });
}

function collectErrorInheritsExceptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.errorInheritsException,
    appliesTo: 'block',
    pattern: /\bclass\s+[\w:]+\s*<\s*(?:::)?Exception\b/g,
  });
}

function collectDuplicateConstantAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateConstantAssignment;
  const facts: ObservedFact[] = [];
  const seenConstants = new Map<string, number>();
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const match = stripped.match(/^\s*([A-Z][A-Z_0-9]*)\s*=\s*(?!=)/);

    if (match && match.index !== undefined) {
      const constName = match[1];
      const lineStartOffset = offset + match.index;

      if (seenConstants.has(constName)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: lineStartOffset + match[0].indexOf(constName),
            endOffset: lineStartOffset + match[0].indexOf(constName) + constName.length,
            text: constName,
          }),
        );
      } else {
        seenConstants.set(constName, lineStartOffset);
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectIoSelectSingleArgFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.ioSelectSingleArg,
    appliesTo: 'block',
    pattern: /\bIO\.select\s*\(\s*\[\s*[^\]]+\]\s*,\s*\[\s*\]\s*,\s*\[\s*\]\s*(?:,\s*[^)]+)?\s*\)/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind: RUBY_BUG_RISK_FACT_KINDS.ioSelectSingleArg,
      appliesTo: 'block',
      pattern: /\bIO\.select\s*\(\s*\[\s*\]\s*,\s*\[\s*[^\]]+\]\s*,\s*\[\s*\]\s*(?:,\s*[^)]+)?\s*\)/g,
    }),
  );
}

function collectBadOperandOrderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.badOperandOrder,
    appliesTo: 'block',
    pattern:
      /\b(?:\d+(?:\.\d+)?|"[^"\n]*"|'[^'\n]*')\s*(?:[+\-*/%]|==|!=|<=|>=|<|>|===)\s*(?!\d)(?!_)[a-zA-Z][a-zA-Z0-9_?!]*/g,
  });
}

function collectDuplicateHashKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateHashKeys;
  const findings: ObservedFact[] = [];

  for (const literal of collectRubyHashLiteralRanges(text)) {
    const seen = new Set<string>();

    for (const key of extractRubyHashKeys(literal.content)) {
      if (seen.has(key.normalized)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: literal.startOffset + key.startOffset,
            endOffset: literal.startOffset + key.endOffset,
            text: key.raw,
          }),
        );
        continue;
      }

      seen.add(key.normalized);
    }
  }

  return findings;
}

interface HashLiteralRange {
  startOffset: number;
  endOffset: number;
  content: string;
}

interface HashKeyMatch {
  raw: string;
  normalized: string;
  startOffset: number;
  endOffset: number;
}

function collectRubyHashLiteralRanges(text: string): HashLiteralRange[] {
  const ranges: HashLiteralRange[] = [];
  const stack: number[] = [];

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (char === '{') {
      stack.push(index);
      continue;
    }

    if (char !== '}' || stack.length === 0) {
      continue;
    }

    const start = stack.pop();
    if (start === undefined) {
      continue;
    }

    const content = text.slice(start + 1, index);
    if (!looksLikeRubyHashLiteral(content)) {
      continue;
    }

    ranges.push({
      startOffset: start,
      endOffset: index + 1,
      content,
    });
  }

  return ranges;
}

function looksLikeRubyHashLiteral(content: string): boolean {
  return /:\w+\s*=>|["'][\w-]+["']\s*=>|\b\w+\s*:/u.test(content);
}

function collectGitInGemspecFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const lines = text.split('\n');
  const facts: ObservedFact[] = [];
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /`git\s/g;

    for (const match of findAllMatches(stripped, pattern)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind: RUBY_BUG_RISK_FACT_KINDS.gitInGemspec,
          startOffset: offset + match.startOffset,
          endOffset: offset + match.endOffset,
          text: match.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectIgnoredColumnAccessedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.ignoredColumnAccessed;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');

  const ignoredColumns = new Set<string>();

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const arrayMatch = stripped.match(
      /self\.ignored_columns\s*\+?=\s*\[([^\]]*)\]/,
    );

    if (arrayMatch) {
      const content = arrayMatch[1];
      for (const symMatch of content.matchAll(/:(\w+)\b/g)) {
        ignoredColumns.add(symMatch[1]);
      }
      for (const strMatch of content.matchAll(/["'](\w+)["']/g)) {
        ignoredColumns.add(strMatch[1]);
      }
    }
  }

  if (ignoredColumns.size === 0) {
    return facts;
  }

  const escapedNames = [...ignoredColumns].map((n) =>
    n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
  );
  const namePattern = escapedNames.join('|');
  const queryMethodPattern =
    /\b(?:find_by|where|pluck|order|select|reorder|joins)\s*\(/;
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);

    if (queryMethodPattern.test(stripped)) {
      const colRefPattern = new RegExp(
        `(?:\\b(${namePattern})\\s*[:=]|:\\s*(${namePattern})\\b)`,
        'g',
      );

      for (const colMatch of findAllMatches(stripped, colRefPattern)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + colMatch.startOffset,
            endOffset: offset + colMatch.endOffset,
            text: colMatch.matchedText,
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectRenamedColumnAccessedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.renamedColumnAccessed,
    appliesTo: 'block',
    pattern: /\brename_column\s+\S+\s*,\s*:(\w+)\s*,/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind: RUBY_BUG_RISK_FACT_KINDS.renamedColumnAccessed,
      appliesTo: 'block',
      pattern: /\bt\.rename\s+:(\w+)\s*,/g,
    }),
  );
}

function collectDeprecatedBigDecimalNewFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedBigDecimalNew,
    appliesTo: 'block',
    pattern: /\bBigDecimal\.new\s*\(/g,
  });
}

function collectSymbolBooleanNameFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.symbolBooleanName,
    appliesTo: 'block',
    pattern: /:true\b|:false\b/g,
  });
}

function collectCircularArgumentReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.circularArgumentReference;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const defMatch = stripped.match(/def\s+\w+[?!]?\s*\(/);

    if (defMatch && defMatch.index !== undefined) {
      const start = defMatch.index + defMatch[0].length;
      const restOfLine = stripped.slice(start);

      let parenCount = 1;
      let endIndex = 0;

      for (let i = 0; i < restOfLine.length; i += 1) {
        const ch = restOfLine[i];
        if (ch === '(') {
          parenCount += 1;
        } else if (ch === ')') {
          parenCount -= 1;
          if (parenCount === 0) {
            endIndex = i;
            break;
          }
        }
      }

      if (parenCount === 0) {
        const signature = restOfLine.slice(0, endIndex);
        const circularArg = /(\w+)\s*[=:]\s*\1\b(?!\()/g;

        for (const match of findAllMatches(signature, circularArg)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + start + match.startOffset,
              endOffset: offset + start + match.endOffset,
              text: match.matchedText,
            }),
          );
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectDeprecatedClassMethodsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.deprecatedClassMethods;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bFile\.exists\?\s*\(|\bDir\.exists\?\s*\(|\biterator\?/g,
  });
}

function collectDisjunctiveAssignmentInConstructorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.disjunctiveAssignmentInConstructor;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inInitialize = false;
  let initializeDepth = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const defMatch = stripped.match(/def\s+initialize\b/);

    if (defMatch) {
      inInitialize = true;
      initializeDepth = countOccurrences(stripped, 'end', 'def');
    } else if (inInitialize) {
      if (stripped.match(/\bend\b/) && initializeDepth > 0) {
        initializeDepth -= 1;
        if (initializeDepth === 0) {
          inInitialize = false;
        }
      } else {
        initializeDepth += countOccurrences(stripped, 'def', 'end');

        const orAssignMatch =
          findAllMatches(stripped, /@\w+\s*\|\|=\s*/g);

        for (const match of orAssignMatch) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + match.startOffset,
              endOffset: offset + match.endOffset,
              text: match.matchedText,
            }),
          );
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function countOccurrences(
  line: string,
  increment: string,
  decrement: string,
): number {
  const inc = (line.match(new RegExp(`\\b${increment}\\b`, 'g')) || []).length;
  const dec = (line.match(new RegExp(`\\b${decrement}\\b`, 'g')) || []).length;
  return Math.max(0, inc - dec);
}

function extractRubyHashKeys(hashContent: string): HashKeyMatch[] {
  const keys: HashKeyMatch[] = [];

  for (const match of hashContent.matchAll(
    /(?:(["'])([^"']+)\1\s*=>)|(?::(\w+)\s*=>)|(?:\b(\w+)\s*:)/gu,
  )) {
    const symbol = match[2] ?? match[3] ?? match[4];
    if (!symbol) {
      continue;
    }

    const raw = match[0];
    const startOffset = match.index ?? 0;

    keys.push({
      raw,
      normalized: symbol.toLowerCase(),
      startOffset,
      endOffset: startOffset + raw.length,
    });
  }

  return keys;
}

function collectDuplicateCaseConditionsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateCaseConditions;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const caseStack: Array<{ conditions: Set<string>; depth: number }> = [];
  let inCase = false;
  let currentCaseConditions: string[] = [];

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const hasCase = /\bcase\b/.test(trimmed);
    if (hasCase) {
      if (inCase) {
        caseStack.push({
          conditions: new Set(currentCaseConditions),
          depth: offset,
        });
      }
      inCase = true;
      currentCaseConditions = [];
    }

    if (inCase) {
      const whenPattern = /\bwhen\s+([^;]*(?:$|(?=;)))/g;
      let whenMatch: RegExpExecArray | null;
      while ((whenMatch = whenPattern.exec(trimmed)) !== null) {
        const conditionText = whenMatch[1].replace(/\s+then\b.*$/, '').trim();
        if (!conditionText) continue;
        const conditions = conditionText.split(/,\s*/);
        for (const cond of conditions) {
          const normalized = cond.replace(/\s+/g, '');
          if (currentCaseConditions.includes(normalized)) {
            const condIndex = stripped.indexOf(cond.trim());
            const lineOffset = condIndex !== -1 ? offset + condIndex : offset;
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'function',
                kind,
                startOffset: lineOffset,
                endOffset: lineOffset + cond.trim().length,
                text: cond.trim(),
              }),
            );
          }
          currentCaseConditions.push(normalized);
        }
      }

      if (/\belse\b/.test(trimmed)) {
        currentCaseConditions = [];
      }

      if (/\bend\b/.test(trimmed)) {
        inCase = caseStack.length > 0;
        if (inCase) {
          const prev = caseStack.pop();
          if (prev) {
            currentCaseConditions = [...prev.conditions];
          }
        } else {
          currentCaseConditions = [];
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectDuplicateMethodDefinitionsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateMethodDefinitions;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  const scopeStack: Array<{ map: Map<string, number>; depth: number }> = [
    { map: new Map(), depth: 0 },
  ];
  let blockDepth = 0;
  const classModulePattern = /\b(?:class|module)\s+\w+/;
  const defPattern = /\bdef\s+([a-zA-Z_]\w*[!?]?)\b/;
  const endPattern = /\bend\b/;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (classModulePattern.test(trimmed)) {
      blockDepth += 1;
      scopeStack.push({ map: new Map(), depth: blockDepth });
    }

    const defMatch = trimmed.match(defPattern);
    if (defMatch) {
      blockDepth += 1;
      const methodName = defMatch[1];
      const currentScope = scopeStack[scopeStack.length - 1].map;
      if (currentScope.has(methodName)) {
        const matchIndex = trimmed.indexOf(methodName);
        if (matchIndex !== -1) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + matchIndex,
              endOffset: offset + matchIndex + methodName.length,
              text: methodName,
            }),
          );
        }
      } else {
        currentScope.set(methodName, offset);
      }
    }

    if (endPattern.test(trimmed)) {
      const endCount = (trimmed.match(/\bend\b/g) || []).length;
      blockDepth = Math.max(0, blockDepth - endCount);
      while (
        scopeStack.length > 1 &&
        scopeStack[scopeStack.length - 1].depth > blockDepth
      ) {
        scopeStack.pop();
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectEachWithObjectImmutableArgFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.eachWithObjectImmutableArg,
    appliesTo: 'block',
    pattern: /\.each_with_object\s*\(\s*(\d[\d._]*|true|false|nil)\s*\)/g,
  });
}

function collectElseFollowedByExpressionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.elseFollowedByExpression,
    appliesTo: 'block',
    pattern: /\belse(?:[ \t;]+(?!#)[ \t]*\S)/g,
  });
}

function collectEmptyEnsureBlockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.emptyEnsureBlock;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const ensurePattern = /\bensure\b/;
  const endPattern = /^\s*end\b/;
  const bodyPattern = /\S/;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);

    if (ensurePattern.test(stripped)) {
      let hasBody = false;
      for (let j = i + 1; j < lines.length; j++) {
        const nextStripped = stripHashLineComment(lines[j]);
        if (endPattern.test(nextStripped)) {
          break;
        }
        if (bodyPattern.test(nextStripped)) {
          hasBody = true;
          break;
        }
      }

      if (!hasBody) {
        const lineStartOffset = offset;
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: lineStartOffset,
            endOffset: lineStartOffset + lines[i].length,
            text: lines[i].trim(),
          }),
        );
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectEmptyExpressionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.emptyExpression;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\(\s*\)/g;

    for (const match of findAllMatches(stripped, pattern)) {
      const before = stripped.slice(0, match.startOffset);
      const lastChar = before[before.length - 1];

      if (
        lastChar &&
        /\w/.test(lastChar)
      ) {
        continue;
      }

      if (/\bdef\s+\w+\s*$/.test(before)) {
        continue;
      }

      if (/->\s*$/.test(before)) {
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + match.startOffset,
          endOffset: offset + match.endOffset,
          text: match.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectEmptyInterpolationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.emptyInterpolation,
    appliesTo: 'block',
    pattern: /#\{\s*\}/g,
  });
}

function collectWhenBranchWithoutBodyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.whenBranchWithoutBody;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inCase = false;
  let pendingWhenStart = -1;
  let pendingWhenLine = -1;
  let caseDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    const caseMatch = trimmed.match(/^case\b/);
    if (caseMatch) {
      inCase = true;
      caseDepth += 1;
    }

    if (!inCase) {
      offset += lines[i].length + 1;
      continue;
    }

    if (pendingWhenStart !== -1) {
      if (/\S/.test(stripped) && !trimmed.startsWith('#') && !trimmed.startsWith('when') && !trimmed.startsWith('else') && !trimmed.startsWith('end')) {
        pendingWhenStart = -1;
        pendingWhenLine = -1;
      } else if (trimmed.startsWith('when') || trimmed.startsWith('else') || trimmed.startsWith('end')) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: pendingWhenStart,
            endOffset: pendingWhenStart + lines[pendingWhenLine].trim().length,
            text: lines[pendingWhenLine].trim(),
          }),
        );
        pendingWhenStart = -1;
        pendingWhenLine = -1;
      }
    }

    const whenMatch = trimmed.match(/^when\s+(.+)/);
    if (whenMatch) {
      const afterWhen = whenMatch[1];
      if (/then\s+\S/.test(afterWhen) && !/then\s*#/.test(afterWhen) && !/then\s*;/.test(afterWhen)) {
        pendingWhenStart = -1;
        pendingWhenLine = -1;
      } else {
        pendingWhenStart = offset + lines[i].search(/\S/);
        pendingWhenLine = i;
      }
    }

    if (trimmed.match(/^end\b/)) {
      caseDepth -= 1;
      if (caseDepth <= 0) {
        inCase = false;
        caseDepth = 0;
        pendingWhenStart = -1;
        pendingWhenLine = -1;
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectEndInMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.endInMethod;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let defIndent = -1;
  let defDepth = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);

    const defMatch = stripped.match(/^(\s*)def\s+\w+/);
    if (defMatch) {
      defDepth += 1;
      if (defDepth === 1) {
        defIndent = defMatch[1].length;
      }
    }

    if (defDepth > 0) {
      const endPattern = new RegExp(`^ {${defIndent}}end\\b`);
      if (endPattern.test(stripped)) {
        defDepth -= 1;
        if (defDepth <= 0) {
          defIndent = -1;
          defDepth = 0;
        }
        offset += line.length + 1;
        continue;
      }

      for (const match of findAllMatches(stripped, /\bEND\b\s*\{/g)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + match.startOffset,
            endOffset: offset + match.endOffset,
            text: match.matchedText,
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectReturnInEnsureFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.returnInEnsure;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inEnsure = false;
  let ensureIndent = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);

    const ensureMatch = stripped.match(/^(\s*)ensure\b/);
    if (ensureMatch) {
      inEnsure = true;
      ensureIndent = ensureMatch[1].length;
    }

    if (inEnsure) {
      const endPattern = new RegExp(`^ {${ensureIndent}}end\\b`);
      if (endPattern.test(stripped)) {
        inEnsure = false;
        offset += line.length + 1;
        continue;
      }

      if (ensureIndent === 0 && /^\s*end\b/.test(stripped)) {
        inEnsure = false;
        offset += line.length + 1;
        continue;
      }

      for (const match of findAllMatches(stripped, /\breturn\b/g)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + match.startOffset,
            endOffset: offset + match.endOffset,
            text: match.matchedText,
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectFlipFlopOperatorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.flipFlopOperator;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /(?:if|unless|while|until)\s.*?(?:==|!=|>=|<=|>|<|=~)\s*.+?\b\s*\.\.\.?\s*.+(?:==|!=|>=|<=|>|<|=~)/g,
  });
}

function collectHeredocMethodOrderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.heredocMethodOrder,
    appliesTo: 'block',
    pattern: /<<[-~]?[A-Z_]\w*\.[a-z_]\w*/g,
  });
}

function collectUnintendedStringConcatenationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.unintendedStringConcatenation,
    appliesTo: 'block',
    pattern:
      /(['"])(?:\\.|(?!\1)[^\\])*?\1\s+(['"])(?:\\.|(?!\2)[^\\])*?\2/g,
  });
}

function collectIneffectiveAccessModifierFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.ineffectiveAccessModifier;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (trimmed.match(/^(private|protected|public)\b/)) {
      const leadingSpaces = stripped.match(/^(\s*)/);
      if (leadingSpaces && leadingSpaces[1].length > 0) {
        offset += line.length + 1;
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + (stripped.length - stripped.trimStart().length),
          endOffset: offset + stripped.length,
          text: stripped.trim(),
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectInterpolationInSingleQuoteFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.interpolationInSingleQuote,
    appliesTo: 'block',
    pattern: /'[^'\n]*#\{[^}]*\}[^'\n]*'/g,
    predicate: (match) => {
      const lineStart = text.lastIndexOf('\n', match.startOffset);
      const lineStartIdx = lineStart === -1 ? 0 : lineStart + 1;
      const beforeMatch = text.slice(lineStartIdx, match.startOffset);
      const quoteCount = (beforeMatch.match(/"/g) || []).length;
      return quoteCount % 2 === 0;
    },
  });
}

function collectNonLocalExitFromIteratorFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.nonLocalExitFromIterator;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const scopeStack: Array<{ depth: number; startOffset: number; isLambda: boolean }> = [];
  const iteratorMethodPattern = /\.(?:each|map|select|reject|find|detect|reduce|inject|collect|any\?|all\?|none\?|one\?|count|sum|flat_map|each_with_index|each_with_object|times|upto|downto|step|grep|partition|sort_by|group_by|tap|yield_self|then)\s*(?:do\b|\{)/g;
  const lambdaPattern = /->\s*(?:\([^)]*\))?\s*\{/g;
  const lambdaDoPattern = /->\s*(?:\([^)]*\))?\s*do\b/g;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const lambdaMatch = trimmed.match(lambdaPattern) || trimmed.match(lambdaDoPattern);
    if (lambdaMatch) {
      scopeStack.push({ depth: 1, startOffset: offset, isLambda: true });
      offset += line.length + 1;
      continue;
    }

    const iterMatch = findAllMatches(stripped, iteratorMethodPattern);
    for (const match of iterMatch) {
      if (/\{$/.test(match.matchedText)) {
        scopeStack.push({ depth: 1, startOffset: offset + match.startOffset, isLambda: false });
      } else if (/do$/.test(match.matchedText)) {
        scopeStack.push({ depth: 1, startOffset: offset + match.startOffset, isLambda: false });
      }
    }

    if (scopeStack.length > 0) {
      const currentScope = scopeStack[scopeStack.length - 1];

      if (currentScope.isLambda) {
        const closeMatch = trimmed.match(/^\s*\}/);
        if (closeMatch) {
          scopeStack.pop();
          offset += line.length + 1;
          continue;
        }
        const endMatch = trimmed.match(/^\s*end\b/);
        if (endMatch) {
          scopeStack.pop();
          offset += line.length + 1;
          continue;
        }
      } else {
        const blockIsBrace = currentScope.depth === 1;

        for (const match of findAllMatches(stripped, /\breturn\b/g)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + match.startOffset,
              endOffset: offset + match.endOffset,
              text: match.matchedText,
            }),
          );
        }

        for (const match of findAllMatches(stripped, /\bbreak\b/g)) {
          const afterBreak = stripped.slice(match.endOffset).trimStart();
          const isModifier = /^(?:if|unless|while|until|rescue)\b/.test(afterBreak);
          const hasValue = !isModifier && /^\w/.test(afterBreak);
          if (!hasValue) {
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'function',
                kind,
                startOffset: offset + match.startOffset,
                endOffset: offset + match.endOffset,
                text: match.matchedText,
              }),
            );
          }
        }

        for (const match of findAllMatches(stripped, /\bnext\b/g)) {
          const afterNext = stripped.slice(match.endOffset).trimStart();
          const isModifier = /^(?:if|unless|while|until|rescue)\b/.test(afterNext);
          const hasValue = !isModifier && /^\w/.test(afterNext);
          if (!hasValue) {
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'function',
                kind,
                startOffset: offset + match.startOffset,
                endOffset: offset + match.endOffset,
                text: match.matchedText,
              }),
            );
          }
        }

        if (blockIsBrace) {
          const closeBrace = findAllMatches(stripped, /\}/g);
          if (closeBrace.length > 0) {
            scopeStack.pop();
          }
        } else {
          const endMatch = findAllMatches(stripped, /\bend\b/g);
          if (endMatch.length > 0) {
            const afterEnd = stripped.slice(endMatch[endMatch.length - 1].endOffset).trim();
            if (!afterEnd || afterEnd === '') {
              scopeStack.pop();
            } else {
              const endCount = (stripped.match(/\bend\b/g) || []).length;
              const doCount = (stripped.match(/\bdo\b/g) || []).length;
              if (endCount > doCount) {
                scopeStack.pop();
              }
            }
          }
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUnsafeNumberConversionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.unsafeNumberConversion,
    appliesTo: 'block',
    pattern: /\b(?:Integer|Float|Rational|Complex)\s*\(/g,
  });
}

function collectBadMagicCommentOrderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.badMagicCommentOrder;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let hasSeenCode = false;
  const magicCommentPattern = /^#\s*(?:frozen_string_literal|encoding|warn_indent|warn_past_scope|shareable_constant_value|experimental)\s*:/i;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed === '' || trimmed.startsWith('#!')) {
      offset += line.length + 1;
      continue;
    }

    if (trimmed.startsWith('#')) {
      if (magicCommentPattern.test(trimmed)) {
        if (hasSeenCode) {
          const contentStart = offset + line.search(/\S/);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: contentStart,
              endOffset: contentStart + trimmed.length,
              text: trimmed,
            }),
          );
        }
      }
      offset += line.length + 1;
      continue;
    }

    hasSeenCode = true;
    offset += line.length + 1;
  }

  return facts;
}

function collectGroupedParenthesesInCallFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.groupedParenthesesInCall;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\b([a-zA-Z_]\w*)\s*\(\s*\(/g;

    for (const match of findAllMatches(stripped, pattern)) {
      const before = stripped.slice(0, match.startOffset).trim();
      if (/\b(?:def|lambda|->|case)\s*$/.test(before) || /\b(?:require|include|extend|attr_reader|attr_writer|attr_accessor)\s+/.test(before)) {
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + match.startOffset,
          endOffset: offset + match.endOffset,
          text: match.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectInvalidPercentStringLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.invalidPercentStringLiteral;
  const facts: ObservedFact[] = [];
  const pairDelimiters: Record<string, string> = { '(': ')', '{': '}', '[': ']', '<': '>' };
  const closePairs = new Set([')', '}', ']', '>']);
  const pattern = /%([qQxrs])([^\s\w])/g;
  let match: RegExpExecArray | null;

  const regex = new RegExp(pattern.source, 'g');
  while ((match = regex.exec(text)) !== null) {
    const percentStart = match.index;
    const delimiter = match[2];
    const pairClose = pairDelimiters[delimiter];
    let depth = 1;
    let pos = percentStart + match[0].length;
    const maxScan = Math.min(pos + 1000, text.length);

    while (pos < maxScan) {
      const ch = text[pos];
      if (ch === '\\') {
        pos += 2;
        continue;
      }
      if (pairClose) {
        if (ch === pairClose) {
          depth -= 1;
          if (depth === 0) {
            break;
          }
        } else if (ch === delimiter) {
          depth += 1;
        }
      } else {
        if (ch === delimiter) {
          depth -= 1;
          if (depth === 0) {
            break;
          }
        }
      }
      pos += 1;
    }

    if (depth > 0) {
      let content: string;
      if (pos >= maxScan && depth > 0) {
        content = text.slice(percentStart, maxScan);
      } else {
        content = text.slice(percentStart, pos + 1);
      }
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: percentStart,
          endOffset: percentStart + content.length,
          text: content,
        }),
      );
    }
  }

  return facts;
}

function collectInvalidPercentSymbolArrayFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.invalidPercentSymbolArray;
  const facts: ObservedFact[] = [];
  const pairDelimiters: Record<string, string> = { '(': ')', '{': '}', '[': ']', '<': '>' };
  const pattern = /%([iIwW])([^\s\w])/g;
  let match: RegExpExecArray | null;

  const regex = new RegExp(pattern.source, 'g');
  while ((match = regex.exec(text)) !== null) {
    const percentStart = match.index;
    const delimiter = match[2];
    const pairClose = pairDelimiters[delimiter];
    let depth = 1;
    let pos = percentStart + match[0].length;
    const maxScan = Math.min(pos + 1000, text.length);

    while (pos < maxScan) {
      const ch = text[pos];
      if (ch === '\\') {
        pos += 2;
        continue;
      }
      if (pairClose) {
        if (ch === pairClose) {
          depth -= 1;
          if (depth === 0) {
            break;
          }
        } else if (ch === delimiter) {
          depth += 1;
        }
      } else {
        if (ch === delimiter) {
          depth -= 1;
          if (depth === 0) {
            break;
          }
        }
      }
      pos += 1;
    }

    if (depth > 0) {
      let content: string;
      if (pos >= maxScan && depth > 0) {
        content = text.slice(percentStart, maxScan);
      } else {
        content = text.slice(percentStart, pos + 1);
      }
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: percentStart,
          endOffset: percentStart + content.length,
          text: content,
        }),
      );
    }
  }

  return facts;
}

function collectUnnecessaryRequireFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unnecessaryRequire;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const seenRequires = new Map<string, number>();
  const requirePattern = /\b(require|require_relative)\s+(["'])([^"']+)\2/g;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);

    if (/\brequire\s+['"]rubygems['"]/.test(stripped)) {
      const gemMatch = stripped.match(/require\s+['"]rubygems['"]/);
      if (gemMatch && gemMatch.index !== undefined) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + gemMatch.index,
            endOffset: offset + gemMatch.index + gemMatch[0].length,
            text: gemMatch[0],
          }),
        );
      }
    }

    let reqMatch: RegExpExecArray | null;
    const reqRegex = new RegExp(requirePattern.source, 'g');
    while ((reqMatch = reqRegex.exec(stripped)) !== null) {
      const moduleName = `${reqMatch[1]}:${reqMatch[3]}`;
      if (seenRequires.has(moduleName)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + reqMatch.index,
            endOffset: offset + reqMatch.index + reqMatch[0].length,
            text: reqMatch[0],
          }),
        );
      } else {
        seenRequires.set(moduleName, offset + reqMatch.index);
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUnnecessarySplatFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unnecessarySplat;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\[\s*\*\s*[a-zA-Z_]\w*\s*\](?!\s*,\s*\w)/g,
    predicate: (match) => {
      const rest = text.slice(match.endOffset).trimStart();
      return !rest.startsWith(',');
    },
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\b\w+\s*\([^)]*\*\s*\[[^\]]*\]/g,
    }),
  );
}

const WITH_INDEX_METHODS =
  'each_with_index|each\\.with_index|map\\.with_index|select\\.with_index|filter_map\\.with_index|flat_map\\.with_index|reduce\\.with_index|inject\\.with_index|collect\\.with_index';

function collectWithIndexValueUnusedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.withIndexValueUnused;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: new RegExp(
      `\\.(?:${WITH_INDEX_METHODS})(?:\\s*\\([^)]*\\))?\\s*\\{[^|{}]*\\|\\s*[^|,\\n]*\\s*\\|`,
      'g',
    ),
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: new RegExp(
        `\\.(?:${WITH_INDEX_METHODS})(?:\\s*\\([^)]*\\))?\\s+do\\s*\\|\\s*[^|,\\n]*\\s*\\|`,
        'g',
      ),
    }),
  );
}

const WITH_OBJECT_METHODS =
  'each_with_object|each\\.with_object|map\\.with_object|select\\.with_object|filter_map\\.with_object|flat_map\\.with_object|reduce\\.with_object|inject\\.with_object|collect\\.with_object';

function collectWithObjectValueUnusedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.withObjectValueUnused;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: new RegExp(
      `\\.(?:${WITH_OBJECT_METHODS})(?:\\s*\\([^)]*\\))?\\s*\\{[^|{}]*\\|\\s*[^|,\\n]*\\s*\\|`,
      'g',
    ),
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: new RegExp(
        `\\.(?:${WITH_OBJECT_METHODS})(?:\\s*\\([^)]*\\))?\\s+do\\s*\\|\\s*[^|,\\n]*\\s*\\|`,
        'g',
      ),
    }),
  );
}

function collectRegexLiteralInConditionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.regexLiteralInCondition,
    appliesTo: 'block',
    pattern: new RegExp(
      '\\b(?:if|unless|while|until)\\s+[^/]*/',
      'g',
    ),
    predicate: (match) => {
      const beforeSlash = match.matchedText.slice(0, match.matchedText.indexOf('/'));
      return !/=~\s*$/.test(beforeSlash.trim());
    },
  });
}

function collectPredicateMethodWithoutParenthesesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.predicateMethodWithoutParentheses,
    appliesTo: 'block',
    pattern: /\.\w+\?\s+\S+/g,
    predicate: (match) => {
      const rest = text.slice(match.endOffset).trimStart();
      return rest.startsWith('&&') || rest.startsWith('||');
    },
  });
}

function collectInvalidRescueTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.invalidRescueType;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\brescue\s+(?:nil|true|false|\d+(?:\.\d+)?)\b/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\brescue\s+["'][^"']*["']/g,
    }),
  );
}

function collectUnsafeSafeNavigationChainFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unsafeSafeNavigationChain;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /[a-zA-Z_]\w*&\.\w+\s*\.\w+/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /[a-zA-Z_]\w*&\.\w+\s*\[/g,
    }),
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /[a-zA-Z_]\w*&\.\w+\s*[+\-*/%]/g,
    }),
  );
}

function collectInconsistentSafeNavigationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.inconsistentSafeNavigation,
    appliesTo: 'block',
    pattern: /([a-zA-Z_]\w*)&\.\w+.*?\1\.\w+/g,
  });
}

function collectSafeNavigationWithEmptyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.safeNavigationWithEmpty,
    appliesTo: 'block',
    pattern: /\b(?:if|unless|while|until)\s+.*?&\.(?:empty|blank|present)\?/g,
  });
}

function collectArgumentOverwrittenBeforeUseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.argumentOverwrittenBeforeUse;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const defMatch = stripped.match(/^\s*def\s+\w+[?!]?\s*\(([^)]*)\)/);
    if (!defMatch) {
      offset += lines[i].length + 1;
      continue;
    }

    const paramsStr = defMatch[1];
    if (!paramsStr.trim()) {
      offset += lines[i].length + 1;
      continue;
    }

    const paramNames = paramsStr.split(',')
      .map(p => {
        const trimmed = p.trim();
        const eqIdx = trimmed.indexOf('=');
        return (eqIdx >= 0 ? trimmed.slice(0, eqIdx) : trimmed).trim();
      })
      .filter(p => /^[a-z_]\w*$/.test(p) && !p.startsWith('_'));

    if (paramNames.length === 0) {
      offset += lines[i].length + 1;
      continue;
    }

    const defIndent = stripped.match(/^\s*/)?.[0].length ?? 0;

    for (let j = i + 1; j < lines.length; j++) {
      const bodyLine = stripHashLineComment(lines[j]);
      const bodyTrimmed = bodyLine.trim();

      if (bodyTrimmed === '' || bodyTrimmed.startsWith('#')) continue;

      const lineIndent = bodyLine.match(/^\s*/)?.[0].length ?? 0;
      if (lineIndent <= defIndent) break;

      if (bodyTrimmed.startsWith('end')) break;

      for (const param of paramNames) {
        const paramPattern = new RegExp(`\\b${param}\\s*(?:=|\\|\\|=)(?!=)\\s`);
        const assignMatch = bodyLine.match(paramPattern);
        if (assignMatch) {
          const col = bodyLine.indexOf(assignMatch[0]);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + col,
              endOffset: offset + col + assignMatch[0].length,
              text: assignMatch[0],
            }),
          );
          break;
        }
      }
      break;
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectBadRescueOrderingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.badRescueOrdering;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const rescueHierarchy: string[] = [];

  const SUPERCLASS_OF: Record<string, string> = {
    StandardError: 'Exception',
    RuntimeError: 'StandardError',
    ArgumentError: 'StandardError',
    TypeError: 'StandardError',
    NameError: 'StandardError',
    NoMethodError: 'NameError',
    IndexError: 'StandardError',
    RangeError: 'StandardError',
    IOError: 'StandardError',
    ZeroDivisionError: 'StandardError',
    LoadError: 'StandardError',
    SystemCallError: 'StandardError',
    SecurityError: 'Exception',
    ScriptError: 'Exception',
    SyntaxError: 'ScriptError',
    FrozenError: 'RuntimeError',
  };

  function isAncestor(ancestor: string, descendant: string): boolean {
    let current = descendant;
    while (current) {
      if (current === ancestor) return true;
      current = SUPERCLASS_OF[current] ?? '';
    }
    return false;
  }

  const endPattern = /\bend\b/;
  let rescueDepth = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/\bbegin\b/.test(trimmed) || /\bdef\s+\w+/.test(trimmed) || /\bdo\b/.test(trimmed)) {
      rescueDepth += 1;
    }

    if (endPattern.test(trimmed)) {
      rescueDepth = Math.max(0, rescueDepth - 1);
      if (rescueDepth === 0) {
        rescueHierarchy.length = 0;
      }
    }

    const rescueMatch = findAllMatches(stripped, /\brescue\s+(::)?(\w+)/g);
    for (const match of rescueMatch) {
      const rescuedClass = match.matchedText.replace(/^rescue\s+/, '').trim();

      for (const prevClass of rescueHierarchy) {
        if (isAncestor(prevClass, rescuedClass)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: offset + match.startOffset,
              endOffset: offset + match.endOffset,
              text: match.matchedText,
            }),
          );
          break;
        }
      }
      rescueHierarchy.push(rescuedClass);
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectOuterVariableShadowedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.outerVariableShadowed;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const outerVars = new Set<string>();

  const varRefPattern = /\b(?:[a-z_]\w*\s*=\s*|[a-z_]\w*\s*\|\|=\s*)/g;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);

    const blockParamMatch = stripped.match(/do\s*\|([^|]+)\|/);
    if (blockParamMatch) {
      const blockParams = blockParamMatch[1].split(',').map(p => p.trim()).filter(p => p.length > 0);
      for (const param of blockParams) {
        if (outerVars.has(param)) {
          const paramIdx = stripped.indexOf(param);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: offset + paramIdx,
              endOffset: offset + paramIdx + param.length,
              text: param,
            }),
          );
        }
      }
    }

    const braceBlockMatch = findAllMatches(stripped, /\{\s*\|([^|]+)\|/g);
    for (const match of braceBlockMatch) {
      const blockParams = match.matchedText.replace(/[{|]/g, '').trim().split(',').map(p => p.trim()).filter(p => p.length > 0);
      for (const param of blockParams) {
        if (outerVars.has(param)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: offset + match.startOffset + match.matchedText.indexOf(param),
              endOffset: offset + match.startOffset + match.matchedText.indexOf(param) + param.length,
              text: param,
            }),
          );
        }
      }
    }

    for (const vMatch of findAllMatches(stripped, varRefPattern)) {
      const varName = vMatch.matchedText.replace(/[=|\s]/g, '').trim();
      if (varName && /^[a-z_]\w*$/.test(varName)) {
        outerVars.add(varName);
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectSuppressedExceptionsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.suppressedExceptions;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    if (!/^rescue\b/.test(trimmed)) {
      offset += lines[i].length + 1;
      continue;
    }

    let hasBody = false;
    const rescueLineOffset = offset + lines[i].search(/\S/);

    for (let j = i + 1; j < lines.length; j++) {
      const bodyLine = stripHashLineComment(lines[j]);
      const bodyTrimmed = bodyLine.trim();

      if (/^end\b/.test(bodyTrimmed)) {
        break;
      }

      if (/\S/.test(bodyTrimmed)) {
        hasBody = true;
        break;
      }
    }

    if (!hasBody) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: rescueLineOffset,
          endOffset: rescueLineOffset + lines[i].trim().length,
          text: lines[i].trim(),
        }),
      );
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectToJsonWithoutArgumentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.toJsonWithoutArgument,
    appliesTo: 'block',
    pattern: /\.to_json\b(?!\s*\()/g,
    predicate: (match) => {
      const afterMatch = text.slice(match.endOffset);
      const lineEnd = afterMatch.indexOf('\n');
      const restOfLine = lineEnd === -1 ? afterMatch : afterMatch.slice(0, lineEnd);
      const cleanRest = restOfLine.split('#')[0];
      return !cleanRest.match(/^\s*\(/);
    },
  });
}

function collectUnreachableCodeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unreachableCode;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const exitKeywords = /\b(?:return|raise|exit|abort|throw|fail)\b/;
  const modifierKeywords = /\b(?:if|unless|while|until|rescue)\b/;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    if (exitKeywords.test(trimmed)) {
      const afterStmt = trimmed.replace(exitKeywords, '').trim();
      const hasModifier = modifierKeywords.test(afterStmt);

      if (!hasModifier) {
        for (let j = i + 1; j < lines.length; j++) {
          const nextLine = stripHashLineComment(lines[j]);
          const nextTrimmed = nextLine.trim();

          if (nextTrimmed === '' || nextTrimmed.startsWith('#')) continue;

          if (/^end\b/.test(nextTrimmed)) break;

          const structuralKeyword = /^(?:ensure|elsif|else|when|rescue)\b/;
          if (structuralKeyword.test(nextTrimmed)) break;

          const lineIndent = nextLine.match(/^\s*/)?.[0].length ?? 0;
          const currentIndent = stripped.match(/^\s*/)?.[0].length ?? 0;

          if (lineIndent >= currentIndent) {
            const nextContentStart = offset + lines[j].length + 1 + nextLine.search(/\S/);
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'function',
                kind,
                startOffset: nextContentStart,
                endOffset: nextContentStart + nextTrimmed.length,
                text: nextTrimmed,
              }),
            );
          }
          break;
        }
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectUnusedMethodArgumentsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unusedMethodArguments;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const defMatch = stripped.match(/^\s*def\s+\w+[?!]?\s*\(([^)]*)\)/);
    if (!defMatch) {
      offset += lines[i].length + 1;
      continue;
    }

    const paramsStr = defMatch[1];
    if (!paramsStr.trim()) {
      offset += lines[i].length + 1;
      continue;
    }

    const params = paramsStr.split(',')
      .map(p => {
        const trimmed = p.trim();
        const eqIdx = trimmed.indexOf('=');
        return (eqIdx >= 0 ? trimmed.slice(0, eqIdx) : trimmed).trim();
      })
      .filter(p => /^_/.test(p));

    if (params.length === 0) {
      offset += lines[i].length + 1;
      continue;
    }

    const methodBody = lines.slice(i + 1).join('\n');
    const strippedBody = stripHashLineComment(methodBody);

    for (const param of params) {
      if (!param.startsWith('_') || param === '_') continue;

      const paramRef = new RegExp(`\\b${param}\\b`);
      if (paramRef.test(strippedBody)) {
        const defLine = stripped;
        const paramIdx = defLine.indexOf(param);
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + paramIdx,
            endOffset: offset + paramIdx + param.length,
            text: param,
          }),
        );
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectUselessAccessModifierFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.uselessAccessModifier;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let lastModifier: string | null = null;
  let classDepth = 0;
  let defDepth = 0;
  const classPattern = /^\s*class\s+\w+/;
  const modulePattern = /^\s*module\s+\w+/;
  const defPattern = /^\s*def\s+\w+/;
  const endPattern = /^\s*end\b/;
  const modifierPattern = /^\s*(private|protected|public)\s*$/;

  for (const line of lines) {
    const trimmed = line.trim();

    if (classPattern.test(trimmed) || modulePattern.test(trimmed)) {
      classDepth += 1;
      lastModifier = null;
    }

    if (defPattern.test(trimmed)) {
      defDepth += 1;
    }

    if (classDepth > 0) {
      const modifierMatch = trimmed.match(modifierPattern);
      if (modifierMatch) {
        const modName = modifierMatch[1];
        if (lastModifier === modName) {
          const lineStart = offset + line.search(/\S/);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: lineStart,
              endOffset: lineStart + modName.length,
              text: modName,
            }),
          );
        }
        lastModifier = modName;
      }
    }

    if (endPattern.test(trimmed)) {
      if (defDepth > 0) {
        defDepth -= 1;
      } else {
        classDepth = Math.max(0, classDepth - 1);
        if (classDepth === 0) {
          lastModifier = null;
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}
