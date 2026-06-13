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
  ambiguousBlockAssociation:
    'ruby.bug-risk.ambiguous-block-association',
  ambiguousOperatorArgument:
    'ruby.bug-risk.ambiguous-operator-argument',
  ambiguousRegexpLiteral:
    'ruby.bug-risk.ambiguous-regexp-literal',
  uselessComparison:
    'ruby.bug-risk.useless-comparison',
  elseWithoutRescue:
    'ruby.bug-risk.else-without-rescue',
  uselessSetterCall:
    'ruby.bug-risk.useless-setter-call',
  mixedRegexCaptures:
    'ruby.bug-risk.mixed-regex-captures',
  unqualifiedConstant:
    'ruby.bug-risk.unqualified-constant',
  duplicateElsifBlock:
    'ruby.bug-risk.duplicate-elsif-block',
  unreachableLoop:
    'ruby.bug-risk.unreachable-loop',
  multipleRescuesForSameException:
    'ruby.bug-risk.multiple-rescues-for-same-exception',
  selfAssignment:
    'ruby.bug-risk.self-assignment',
  identicalBinaryOperands:
    'ruby.bug-risk.identical-binary-operands',
  branchesWithoutBody:
    'ruby.bug-risk.branches-without-body',
  trailingCommaAttribute:
    'ruby.bug-risk.trailing-comma-attribute',
  equalInsteadOfEqual:
    'ruby.bug-risk.equal-instead-of-equal',
  invalidIntegerTimes:
    'ruby.bug-risk.invalid-integer-times',
  constantInBlock:
    'ruby.bug-risk.constant-in-block',
  callbackOrder:
    'ruby.bug-risk.callback-order',
  routesMatchSingleVerb:
    'ruby.bug-risk.routes-match-single-verb',
  redundantForeignKey:
    'ruby.bug-risk.redundant-foreign-key',
  callbackOverride:
    'ruby.bug-risk.callback-override',
  irreversibleMigration:
    'ruby.bug-risk.irreversible-migration',
  nonNullColumnWithoutDefault:
    'ruby.bug-risk.non-null-column-without-default',
  consoleOutputInsteadOfLogger:
    'ruby.bug-risk.console-output-instead-of-logger',
  incorrectPluralization:
    'ruby.bug-risk.incorrect-pluralization',
  usePresenceOverExplicitCheck:
    'ruby.bug-risk.use-presence-over-explicit-check',
  usePresentToSimplifyConditional:
    'ruby.bug-risk.use-present-to-simplify-conditional',
  rakeTaskMissingEnvironment:
    'ruby.bug-risk.rake-task-missing-environment',
  useSquareBracketsForAttributes:
    'ruby.bug-risk.use-square-brackets-for-attributes',
  redundantAllowNil:
    'ruby.bug-risk.redundant-allow-nil',
  plainMethodInsteadOfProc:
    'ruby.bug-risk.plain-method-instead-of-proc',
  timeWithoutZone:
    'ruby.bug-risk.time-without-zone',
  invalidRailsEnvPredicate:
    'ruby.bug-risk.invalid-rails-env-predicate',
  oldStyleValidationMacro:
    'ruby.bug-risk.old-style-validation-macro',
  deprecatedFilterMethods:
    'ruby.bug-risk.deprecated-filter-methods',
  activeRecordAlias:
    'ruby.bug-risk.active-record-alias',
  activeRecordMethodOverride:
    'ruby.bug-risk.active-record-method-override',
  activeSupportAlias:
    'ruby.bug-risk.active-support-alias',
  controllerBaseSubclass:
    'ruby.bug-risk.controller-base-subclass',
  activeJobBaseSubclass:
    'ruby.bug-risk.active-job-base-subclass',
  actionMailerBaseSubclass:
    'ruby.bug-risk.action-mailer-base-subclass',
  activeRecordBaseSubclass:
    'ruby.bug-risk.active-record-base-subclass',
  assertNotUsage:
    'ruby.bug-risk.assert-not-usage',
  deprecatedBelongsToRequired:
    'ruby.bug-risk.deprecated-belongs-to-required',
  useBlankSimplify:
    'ruby.bug-risk.use-blank-simplify',
  alterQueriesCombine:
    'ruby.bug-risk.alter-queries-combine',
  tableWithoutTimestamps:
    'ruby.bug-risk.table-without-timestamps',
  badDateUsage:
    'ruby.bug-risk.bad-date-usage',
  useDelegate:
    'ruby.bug-risk.use-delegate',
  allEachToFindEach:
    'ruby.bug-risk.all-each-to-find-each',
  allowBlankWithDelegate:
    'ruby.bug-risk.allow-blank-with-delegate',
  deprecatedFindByDynamic:
    'ruby.bug-risk.deprecated-find-by-dynamic',
  enumArraySyntax:
    'ruby.bug-risk.enum-array-syntax',
  enumDuplicateValues:
    'ruby.bug-risk.enum-duplicate-values',
  exitInAppCode:
    'ruby.bug-risk.exit-in-app-code',
  railsEnvEquality:
    'ruby.bug-risk.rails-env-equality',
  railsRootJoin:
    'ruby.bug-risk.rails-root-join',
  whereFirstOverFindBy:
    'ruby.bug-risk.where-first-over-find-by',
  hasAndBelongsToMany:
    'ruby.bug-risk.has-and-belongs-to-many',
  dependentOptionCascade:
    'ruby.bug-risk.dependent-option-cascade',
  helperInstanceVariables:
    'ruby.bug-risk.helper-instance-variables',
  httpMethodsWithoutParams:
    'ruby.bug-risk.http-methods-without-params',
  deprecatedHttpStatusSymbols:
    'ruby.bug-risk.deprecated-http-status-symbols',
  skipFilterConditional:
    'ruby.bug-risk.skip-filter-conditional',
  missingInverseOf:
    'ruby.bug-risk.missing-inverse-of',
  undefinedActionFilter:
    'ruby.bug-risk.undefined-action-filter',
  redundantWithOptionsReceiver:
    'ruby.bug-risk.redundant-with-options-receiver',
  classNameShouldBeString:
    'ruby.bug-risk.class-name-should-be-string',
  nonPreferredAssertFalseness:
    'ruby.bug-risk.non-preferred-assert-falseness',
  relativeDateAsConstant:
    'ruby.bug-risk.relative-date-as-constant',
  inconsistentRequestReferrer:
    'ruby.bug-risk.inconsistent-request-referrer',
  inconsistentSafeNavigationTry:
    'ruby.bug-risk.inconsistent-safe-navigation-try',
  safeNavigationWithBlank:
    'ruby.bug-risk.safe-navigation-with-blank',
} as const;

const RESCUE_EXCEPTION_CLASS_NAMES =
  'StandardError|Exception|RuntimeError|ArgumentError|NameError|TypeError|NoMethodError|IOError|IndexError|RangeError|RegexpError|SyntaxError|LoadError|ZeroDivisionError|NotImplementedError|ScriptError|SecurityError|SystemCallError|SystemStackError|ThreadError|FrozenError|LocalJumpError';

export interface CollectRubyBugRiskFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRubyBugRiskFacts(
  options: CollectRubyBugRiskFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

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
    ...collectAmbiguousBlockAssociationFacts(text, detector),
    ...collectAmbiguousOperatorArgumentFacts(text, detector),
    ...collectAmbiguousRegexpLiteralFacts(text, detector),
    ...collectUselessComparisonFacts(text, detector),
    ...collectElseWithoutRescueFacts(text, detector),
    ...collectUselessSetterCallFacts(text, detector),
    ...collectMixedRegexCapturesFacts(text, detector),
    ...collectUnqualifiedConstantFacts(text, detector),
    ...collectDuplicateElsifBlockFacts(text, detector),
    ...collectUnreachableLoopFacts(text, detector),
    ...collectMultipleRescuesForSameExceptionFacts(text, detector),
    ...collectSelfAssignmentFacts(text, detector),
    ...collectIdenticalBinaryOperandsFacts(text, detector),
    ...collectBranchesWithoutBodyFacts(text, detector),
    ...collectTrailingCommaAttributeFacts(text, detector),
    ...collectEqualInsteadOfEqualFacts(text, detector),
    ...collectInvalidIntegerTimesFacts(text, detector),
    ...collectConstantInBlockFacts(text, detector),
    ...collectCallbackOrderFacts(text, detector),
    ...collectRoutesMatchSingleVerbFacts(text, detector, path),
    ...collectRedundantForeignKeyFacts(text, detector),
    ...collectCallbackOverrideFacts(text, detector),
    ...collectIrreversibleMigrationFacts(text, detector, path),
    ...collectNonNullColumnWithoutDefaultFacts(text, detector),
    ...collectConsoleOutputInsteadOfLoggerFacts(text, detector),
    ...collectIncorrectPluralizationFacts(text, detector),
    ...collectUsePresenceOverExplicitCheckFacts(text, detector),
    ...collectUsePresentToSimplifyConditionalFacts(text, detector),
    ...collectRakeTaskMissingEnvironmentFacts(text, detector, path),
    ...collectUseSquareBracketsForAttributesFacts(text, detector),
    ...collectRedundantAllowNilFacts(text, detector),
    ...collectPlainMethodInsteadOfProcFacts(text, detector),
    ...collectTimeWithoutZoneFacts(text, detector),
    ...collectInvalidRailsEnvPredicateFacts(text, detector),
    ...collectOldStyleValidationMacroFacts(text, detector),
    ...collectDeprecatedFilterMethodsFacts(text, detector),
    ...collectActiveRecordAliasFacts(text, detector),
    ...collectActiveRecordMethodOverrideFacts(text, detector),
    ...collectActiveSupportAliasFacts(text, detector),
    ...collectControllerBaseSubclassFacts(text, detector),
    ...collectActiveJobBaseSubclassFacts(text, detector),
    ...collectActionMailerBaseSubclassFacts(text, detector),
    ...collectActiveRecordBaseSubclassFacts(text, detector),
    ...collectAssertNotUsageFacts(text, detector),
    ...collectDeprecatedBelongsToRequiredFacts(text, detector),
    ...collectUseBlankSimplifyFacts(text, detector),
    ...collectAlterQueriesCombineFacts(text, detector, path),
    ...collectTableWithoutTimestampsFacts(text, detector, path),
    ...collectBadDateUsageFacts(text, detector),
    ...collectUseDelegateFacts(text, detector),
    ...collectAllowBlankWithDelegateFacts(text, detector),
    ...collectAllEachToFindEachFacts(text, detector),
    ...collectDeprecatedFindByDynamicFacts(text, detector),
    ...collectEnumArraySyntaxFacts(text, detector),
    ...collectEnumDuplicateValuesFacts(text, detector),
    ...collectExitInAppCodeFacts(text, detector),
    ...collectRailsEnvEqualityFacts(text, detector),
    ...collectRailsRootJoinFacts(text, detector),
    ...collectWhereFirstOverFindByFacts(text, detector),
    ...collectHasAndBelongsToManyFacts(text, detector),
    ...collectDependentOptionCascadeFacts(text, detector),
    ...collectHelperInstanceVariablesFacts(text, detector),
    ...collectHttpMethodsWithoutParamsFacts(text, detector),
    ...collectDeprecatedHttpStatusSymbolsFacts(text, detector),
    ...collectSkipFilterConditionalFacts(text, detector),
    ...collectMissingInverseOfFacts(text, detector),
    ...collectUndefinedActionFilterFacts(text, detector),
    ...collectRedundantWithOptionsReceiverFacts(text, detector),
    ...collectClassNameShouldBeStringFacts(text, detector),
    ...collectNonPreferredAssertFalsenessFacts(text, detector, path),
    ...collectRelativeDateAsConstantFacts(text, detector),
    ...collectInconsistentRequestReferrerFacts(text, detector),
    ...collectInconsistentSafeNavigationTryFacts(text, detector),
    ...collectSafeNavigationWithBlankFacts(text, detector),
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

function collectAmbiguousBlockAssociationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.ambiguousBlockAssociation,
    appliesTo: 'block',
    pattern: /\b(?!(?:if|unless|while|until|case|and|or|not|def|class|module|return|break|next|redo)\b)\w+[?!]?[ \t]+\w+[?!]?(?:[ \t]*\{\s*\||[ \t]+do\s+\|)/g,
  });
}

function collectAmbiguousOperatorArgumentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.ambiguousOperatorArgument;
  const lines = text.split('\n');
  const facts: ObservedFact[] = [];
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\b\w+[?!]?[ \t]+[+\-!~][a-zA-Z_]\w*/g;

    for (const match of findAllMatches(stripped, pattern)) {
      const before = stripped.slice(0, match.startOffset).trim();
      if (/[,([{=+\-*/%<>!~|&^?:]\s*$/.test(before)) {
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

function collectAmbiguousRegexpLiteralFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.ambiguousRegexpLiteral;
  const lines = text.split('\n');
  const facts: ObservedFact[] = [];
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\b(?!(?:if|unless|while|until|case|and|or|not|return|break|next)\b)\w+[?!]?[ \t]+\/[^/\n]{2,}\/[a-z]*/g;

    for (const match of findAllMatches(stripped, pattern)) {
      const before = stripped.slice(0, match.startOffset).trim();
      if (/[0-9)]$/.test(before) || /[,([{=+\-*/%<>\s]\s*$/.test(before)) {
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

function collectUselessComparisonFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.uselessComparison;
  const lines = text.split('\n');
  const facts: ObservedFact[] = [];
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const pattern = /\b([a-zA-Z_]\w*(?:\.\w+)*)\s*(==|!=|>|<|>=|<=|===)\s*\1\b/g;

    for (const match of findAllMatches(stripped, pattern)) {
      // Skip if the matched symbols contain a dot (method chain) to avoid FP
      if (match.matchedText.includes('.')) {
        continue;
      }
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

    offset += line.length + 1;
  }

  return facts;
}

function collectElseWithoutRescueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.elseWithoutRescue;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inBegin = false;
  let beginIndent = -1;
  let hasRescue = false;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/^begin\b/.test(trimmed)) {
      inBegin = true;
      beginIndent = stripped.search(/\S/);
      hasRescue = false;
      offset += line.length + 1;
      continue;
    }

    if (inBegin) {
      const lineIndent = stripped.search(/\S/);

      if (/^rescue\b/.test(trimmed)) {
        hasRescue = true;
        offset += line.length + 1;
        continue;
      }

      if (/^else\b/.test(trimmed) && !hasRescue) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + stripped.search(/\S/),
            endOffset: offset + stripped.search(/\S/) + 4,
            text: 'else',
          }),
        );
        offset += line.length + 1;
        continue;
      }

      if (/^end\b/.test(trimmed) || (lineIndent <= beginIndent && !/^\s*$/.test(stripped))) {
        inBegin = false;
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUselessSetterCallFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.uselessSetterCall,
    appliesTo: 'function',
    pattern: /(?:self\.(\w+)|@(\w+))\s*=\s*(?:self\.\1|@\2)(?!\s*(?:\.|\())|(?:self\.(\w+)|@(\w+))\s*=\s*\3\s*\|\|\s*|@(\w+)\s*=\s*@\5\s*$/gm,
    predicate: (match) => {
      const rest = text.slice(match.endOffset).split('\n')[0];
      // Skip if there are method calls or operators on the right side
      return !/\s*\.\s*\w+\s*\(/.test(rest) && !/\s*[+\-*/%]\s*/.test(rest);
    },
  });
}

function collectMixedRegexCapturesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.mixedRegexCaptures;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const regexPattern = /\/((?:[^/\\]|\\.)*)\/([a-z]*)/g;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    let regMatch: RegExpExecArray | null;

    while ((regMatch = regexPattern.exec(stripped)) !== null) {
      const pattern = regMatch[1];
      const hasNamed = /\?<\w+>/.test(pattern);
      const hasNumbered = /\((?!\?)/.test(pattern);

      if (hasNamed && hasNumbered) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + regMatch.index,
            endOffset: offset + regMatch.index + regMatch[0].length,
            text: regMatch[0],
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUnqualifiedConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unqualifiedConstant;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  const qualifiedConstants = new Set<string>();
  const fileDefinedClasses = new Set<string>();
  const moduleMatch = text.match(/module\s+(\w+)/);
  const currentModule = moduleMatch ? moduleMatch[1] : null;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    // Collect class definitions
    const classDefMatch = trimmed.match(/^class\s+(?:::)?(\w+)/);
    if (classDefMatch) {
      fileDefinedClasses.add(classDefMatch[1]);
    }

    // Collect references to namespaced constants
    const qualifiedMatch = findAllMatches(stripped, /\b(\w+)::\w+/g);
    for (const match of qualifiedMatch) {
      qualifiedConstants.add(match.matchedText.split('::')[0]);
    }

    // Check for class inheritance with bare constants
    if (currentModule && trimmed.startsWith('class')) {
      const inheritMatch = trimmed.match(/class\s+\w+\s*<\s*(\w+)/);
      if (inheritMatch) {
        const parentClass = inheritMatch[1];
        if (!fileDefinedClasses.has(parentClass) && !qualifiedConstants.has(parentClass) && parentClass !== 'Object' && parentClass !== 'Struct') {
          const idx = stripped.indexOf(parentClass);
          facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + idx,
            endOffset: offset + idx + parentClass.length,
            text: parentClass,
          }),
        );
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectDuplicateElsifBlockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.duplicateElsifBlock;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let conditionStack: string[] = [];

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const elsifMatch = trimmed.match(/^elsif\s+(.+?)(?:\s+then\b)?$/);
    if (elsifMatch) {
      const condition = elsifMatch[1].replace(/\s+/g, '');

      if (conditionStack.length > 0 && conditionStack[conditionStack.length - 1] === condition) {
        const idx = stripped.indexOf('elsif');
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + idx,
            endOffset: offset + idx + 5,
            text: 'elsif',
          }),
        );
      }

      conditionStack.push(condition);
    }

    if (/^end\b/.test(trimmed)) {
      conditionStack = [];
    }

    if (/^if\b/.test(trimmed)) {
      conditionStack = [];
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUnreachableLoopFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.unreachableLoop;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const loopStack: Array<{ indent: number; foundFirstStmt: boolean }> = [];

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    // Detect loop starts
    const loopMatch = trimmed.match(/^\s*(?:while|until)\s+/);
    const forMatch = trimmed.match(/^\s*for\s+/);
    const loopDoMatch = trimmed.match(/(?:loop|times|upto|downto|each|map)\s+(?:do|\{)/);

    if (loopMatch || forMatch) {
      const indent = stripped.search(/\S/);
      loopStack.push({ indent, foundFirstStmt: false });
      offset += lines[i].length + 1;
      continue;
    }

    if (loopDoMatch) {
      const indent = stripped.search(/\S/);
      loopStack.push({ indent, foundFirstStmt: false });
      offset += lines[i].length + 1;
      continue;
    }

    // Check loop body
    if (loopStack.length > 0) {
      const currentLoop = loopStack[loopStack.length - 1];
      const lineIndent = stripped.search(/\S/);

      if (lineIndent > currentLoop.indent && !currentLoop.foundFirstStmt && /\S/.test(trimmed) && !trimmed.startsWith('#') && !trimmed.startsWith('end')) {
        currentLoop.foundFirstStmt = true;

        // Check if first statement is unconditional exit
        if (/^\s*(?:return|break|raise|throw|exit|abort|fail)\b/.test(stripped) && !/\b(?:if|unless|while|until|rescue)\b/.test(stripped.slice(stripped.search(/\S/)).slice(6))) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + stripped.search(/\S/),
              endOffset: offset + stripped.search(/\S/) + 6,
              text: stripped.trim().split(/\s/)[0],
            }),
          );
        }
      }

      if (lineIndent <= currentLoop.indent && /^end\b/.test(trimmed)) {
        loopStack.pop();
      } else if (lineIndent <= currentLoop.indent && /\S/.test(trimmed) && !trimmed.startsWith('#')) {
        loopStack.pop();
      }
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectMultipleRescuesForSameExceptionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.multipleRescuesForSameException;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let rescueClasses: string[] = [];
  let blockDepth = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/\b(?:begin|def\s+\w+|do\b)/.test(trimmed) && !/\bthen\b/.test(trimmed)) {
      blockDepth += 1;
      if (/\b(?:begin|def\s+\w+)/.test(trimmed)) {
        rescueClasses = [];
      }
    }

    if (/^end\b/.test(trimmed)) {
      blockDepth = Math.max(0, blockDepth - 1);
      if (blockDepth === 0) {
        rescueClasses = [];
      }
    }

    const rescueMatch = trimmed.match(/^rescue\s+(?:::)?(\w+)(?:\s*=>\s*\w+)?(?:\s*,\s*(?:::)?(\w+))?/);
    if (rescueMatch) {
      for (let g = 1; g < rescueMatch.length; g++) {
        const excName = rescueMatch[g];
        if (excName && rescueClasses.includes(excName)) {
          const idx = stripped.indexOf(excName);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: offset + (idx >= 0 ? idx : trimmed.indexOf('rescue')),
              endOffset: offset + (idx >= 0 ? idx + excName.length : trimmed.indexOf('rescue') + 6),
              text: excName,
            }),
          );
        }
      }

      for (let g = 1; g < rescueMatch.length; g++) {
        if (rescueMatch[g] && !rescueClasses.includes(rescueMatch[g])) {
          rescueClasses.push(rescueMatch[g]);
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectSelfAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.selfAssignment;

  return collectMatchedFacts({
    text, detector, kind,
    appliesTo: 'block',
    pattern: /(\b[a-z_]\w*)\s*=\s*\1\b(?!\w)/g,
    predicate: (match) => {
      const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
      const linePrefix = text.slice(lineStart, match.startOffset);
      if (/^\s*def\b/.test(linePrefix)) return false;
      const rest = text.slice(match.endOffset).split('\n')[0];
      return !/\s*(?:[+\-*/%|&^]|<=>|and|or)\s/.test(rest) && !rest.startsWith('.');
    },
  }).concat(
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[A-Z]\w*)\s*=\s*\1\b(?!\w)/g,
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[a-z_]\w*)\s*,\s*(\b[a-z_]\w*)\s*=\s*\1\s*,\s*\2\b(?!\w)/g,
    }),
  );
}

function collectIdenticalBinaryOperandsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.identicalBinaryOperands;

  return collectMatchedFacts({
    text, detector, kind,
    appliesTo: 'block',
    pattern: /(\b[a-zA-Z_]\w*)[ \t]*([+\-*/%])[ \t]*\1\b(?!\w)/g,
    predicate: (m) => !m.matchedText.includes('\n'),
  }).concat(
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[a-zA-Z_]\w*)[ \t]*(\|)[ \t]*\1\b(?!\w)(?!\|)/g,
      predicate: (m) => {
        if (m.matchedText.includes('\n')) return false;
        if (text[m.startOffset - 1] === '|') return false;
        const pipeIdx = m.matchedText.indexOf('|');
        if (pipeIdx > 0 && /\w/.test(m.matchedText[pipeIdx - 1])) return false;
        return true;
      },
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[a-zA-Z_]\w*)[ \t]*(&)[ \t]*\1\b(?!\w)(?!&)/g,
      predicate: (m) => !m.matchedText.includes('\n'),
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[a-zA-Z_]\w*)[ \t]*(\^)[ \t]*\1\b(?!\w)/g,
      predicate: (m) => !m.matchedText.includes('\n'),
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /(\b[a-zA-Z_]\w*)[ \t]*(<=>)[ \t]*\1\b(?!\w)/g,
      predicate: (m) => !m.matchedText.includes('\n'),
    }),
  );
}

function collectBranchesWithoutBodyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.branchesWithoutBody;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let pendingStart = -1;
  let pendingLine = -1;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    if (/^\s*\S/.test(lines[i]) && /^(?!if|unless|elsif|end|else|when)\s*\S.*\s+(?:if|unless)\s+/.test(lines[i])) {
      offset += lines[i].length + 1;
      continue;
    }

    if (pendingStart !== -1) {
      if (/\S/.test(trimmed) && !trimmed.startsWith('#')) {
        if (/^(?:end|elsif|else)\b/.test(trimmed)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'function',
              kind,
              startOffset: pendingStart,
              endOffset: pendingStart + lines[pendingLine].trim().length,
              text: lines[pendingLine].trim(),
            }),
          );
        }
        pendingStart = -1;
        pendingLine = -1;
      }
    }

    if (/^(?:if|unless)\s+/.test(trimmed) && !/\bthen\b/.test(trimmed)) {
      pendingStart = offset + stripped.search(/\S/);
      pendingLine = i;
    } else if (/^elsif\s+/.test(trimmed)) {
      pendingStart = offset + stripped.search(/\S/);
      pendingLine = i;
    }

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectTrailingCommaAttributeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.trailingCommaAttribute,
    appliesTo: 'block',
    pattern: /\b(?:attr_reader|attr_writer|attr_accessor)\s+(?:(?::\w+)\s*,\s*)*(?::\w+)\s*,(?!\s*:)/g,
  });
}

function collectEqualInsteadOfEqualFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.equalInsteadOfEqual,
    appliesTo: 'block',
    pattern: /(\w+)\.object_id\s*==\s*\1\.object_id/g,
  });
}

function collectInvalidIntegerTimesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.invalidIntegerTimes;

  return collectMatchedFacts({
    text, detector, kind,
    appliesTo: 'block',
    pattern: /\b0\.times\b(?!\.)/g,
  }).concat(
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /\b1\.times\b(?!\.)/g,
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /\b0x0\.times\b/g,
    }),
    collectMatchedFacts({
      text, detector, kind,
      appliesTo: 'block',
      pattern: /\b-1\.times\b(?!\.)/g,
    }),
  );
}

function collectConstantInBlockFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.constantInBlock;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inDef = false;
  let defDepth = 0;

  const moduleClassPattern = /^\s*(?:class|module)\s+(?:::)?[A-Z]\w*/;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (moduleClassPattern.test(trimmed)) {
      offset += line.length + 1;
      continue;
    }

    if (/^\s*def\s+/.test(trimmed)) {
      inDef = true;
      defDepth += 1;
      offset += line.length + 1;
      continue;
    }

    if (inDef && /^\s*end\b/.test(trimmed)) {
      defDepth -= 1;
      if (defDepth <= 0) {
        inDef = false;
        defDepth = 0;
      }
      offset += line.length + 1;
      continue;
    }

    if (inDef) {
      const constMatch = trimmed.match(/\b([A-Z]\w*)\s*=(?![=>])\s*/);
      if (constMatch) {
        const idx = stripped.indexOf(constMatch[1]);
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'function',
            kind,
            startOffset: offset + idx,
            endOffset: offset + idx + constMatch[1].length,
            text: constMatch[1],
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectCallbackOrderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.callbackOrder;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inClass = false;
  let classDepth = 0;
  const callbackWeights: Map<string, number> = new Map([
    ['before_validation', 1],
    ['after_validation', 2],
    ['before_save', 3],
    ['around_save', 4],
    ['before_create', 5],
    ['around_create', 6],
    ['after_create', 7],
    ['after_save', 8],
    ['after_commit', 9],
    ['after_rollback', 10],
  ]);
  const callbackOrder: Array<{ name: string; weight: number; offset: number; length: number }> = [];

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/^\s*class\s+/.test(trimmed)) {
      inClass = true;
      classDepth += 1;
      offset += line.length + 1;
      continue;
    }

    if (inClass && /^\s*end\b/.test(trimmed)) {
      classDepth -= 1;
      if (classDepth <= 0) {
        for (let i = 0; i < callbackOrder.length - 1; i++) {
          for (let j = i + 1; j < callbackOrder.length; j++) {
            if (callbackOrder[i].weight > callbackOrder[j].weight) {
              facts.push(
                createOffsetFact(text, {
                  detector,
                  appliesTo: 'block',
                  kind,
                  startOffset: callbackOrder[j].offset,
                  endOffset: callbackOrder[j].offset + callbackOrder[j].length,
                  text: callbackOrder[j].name,
                }),
              );
            }
          }
        }
        inClass = false;
        classDepth = 0;
        callbackOrder.length = 0;
      }
      offset += line.length + 1;
      continue;
    }

    if (inClass) {
      for (const [name, weight] of callbackWeights) {
        const cbMatch = trimmed.match(new RegExp(`\\b${name}\\s+(?::\\w+\\s*,?\\s*)*`));
        if (cbMatch) {
          const idx = stripped.indexOf(name);
          callbackOrder.push({
            name,
            weight,
            offset: offset + (idx >= 0 ? idx : 0),
            length: name.length,
          });
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectRoutesMatchSingleVerbFacts(
  text: string,
  detector: string,
  path?: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.routesMatchSingleVerb;

  if (!path || !path.includes('routes')) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    predicate: (match) => {
      const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
      const lineEnd = text.indexOf('\n', match.startOffset);
      const line = text.slice(lineStart, lineEnd >= 0 ? lineEnd : undefined);
      return !/via:\s*:all\b/.test(line) && !/via:\s*\[[^\]]*,[^\]]*\]/.test(line);
    },
    pattern: /^\s*match\b/gm,
  });
}

function collectRedundantForeignKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.redundantForeignKey;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:has_many|has_one|belongs_to)\s+:(\w+).*?foreign_key:\s*['"](\w+)['"]/g,
    predicate: (match) => {
      const textAround = match.matchedText;
      const reexec = new RegExp(/\b(?:has_many|has_one|belongs_to)\s+:(\w+).*?foreign_key:\s*['"](\w+)['"]/);
      const parts = textAround.match(reexec);
      const assocName = parts?.[1] ?? '';
      const fkValue = parts?.[2] ?? '';
      const conventionFk = `${assocName}_id`;
      return fkValue === conventionFk;
    },
  });
}

function collectCallbackOverrideFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.callbackOverride;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inClass = false;
  let classDepth = 0;
  const afterCommitMethods: Map<string, number> = new Map();

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/^\s*class\s+/.test(trimmed)) {
      inClass = true;
      classDepth += 1;
      afterCommitMethods.clear();
      offset += line.length + 1;
      continue;
    }

    if (inClass && /^\s*end\b/.test(trimmed)) {
      classDepth -= 1;
      if (classDepth <= 0) {
        inClass = false;
        classDepth = 0;
        afterCommitMethods.clear();
      }
      offset += line.length + 1;
      continue;
    }

    if (inClass) {
      const cbMatch = trimmed.match(
        /\b(after_commit|after_create_commit|after_update_commit|after_destroy_commit)\s+(:\w+)/,
      );
      if (cbMatch) {
        const methodName = cbMatch[2];
        const firstOffset = afterCommitMethods.get(methodName);
        if (firstOffset !== undefined) {
          const idx = stripped.indexOf(cbMatch[1]);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: offset + (idx >= 0 ? idx : 0),
              endOffset: offset + (idx >= 0 ? idx : 0) + cbMatch[1].length,
              text: cbMatch[1],
            }),
          );
        } else {
          const idx = stripped.indexOf(cbMatch[1]);
          afterCommitMethods.set(methodName, offset + (idx >= 0 ? idx : 0));
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectIrreversibleMigrationFacts(
  text: string,
  detector: string,
  path?: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.irreversibleMigration;

  if (!path || !path.includes('db/migrate')) {
    return [];
  }

  const lines = text.split('\n');
  const facts: ObservedFact[] = [];
  let offset = 0;
  let inMigrationClass = false;
  let classDepth = 0;
  let defDepth = 0;
  let hasUp = false;
  let hasDown = false;
  let hasChange = false;
  let migrationStartOffset = 0;
  let inChangeMethod = false;

  const IRREVERSIBLE_OPS =
    /\b(?:drop_table|remove_column|rename_column|change_column|change_table|remove_index|remove_belongs_to|remove_reference|execute)\b/g;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/^\s*class\s+\w+\s*<\s*(?:::)?ActiveRecord::Migration/.test(trimmed)) {
      inMigrationClass = true;
      classDepth = stripped.search(/\S/);
      defDepth = 0;
      hasUp = false;
      hasDown = false;
      hasChange = false;
      inChangeMethod = false;
      migrationStartOffset = offset + classDepth;
      offset += line.length + 1;
      continue;
    }

    if (inMigrationClass) {
      if (/^\s*class\b/.test(trimmed)) {
        classDepth += 1;
        offset += line.length + 1;
        continue;
      }

      if (/^\s*def\s+/.test(trimmed)) {
        defDepth += 1;
        if (/^\s*def\s+change\b/.test(trimmed)) {
          hasChange = true;
          inChangeMethod = true;
        } else if (/^\s*def\s+up\b/.test(trimmed)) {
          hasUp = true;
          inChangeMethod = false;
        } else if (/^\s*def\s+down\b/.test(trimmed)) {
          hasDown = true;
          inChangeMethod = false;
        } else {
          inChangeMethod = false;
        }
        offset += line.length + 1;
        continue;
      }

      if (/^\s*end\b/.test(trimmed)) {
        if (defDepth > 0) {
          defDepth -= 1;
          if (defDepth === 0) {
            inChangeMethod = false;
          }
        } else {
          classDepth -= 1;
          if (classDepth <= 0) {
            if (!hasChange && (hasUp !== hasDown)) {
              facts.push(
                createOffsetFact(text, {
                  detector,
                  appliesTo: 'block',
                  kind,
                  startOffset: migrationStartOffset,
                  endOffset: offset + 3,
                  text: text.slice(migrationStartOffset, offset + 3).split('\n')[0].trim(),
                }),
              );
            }
            inMigrationClass = false;
            classDepth = 0;
          }
        }
        offset += line.length + 1;
        continue;
      }

      if (inChangeMethod) {
        for (const match of findAllMatches(stripped, IRREVERSIBLE_OPS)) {
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
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

const COLUMN_TYPE_METHODS =
  'string|integer|text|boolean|datetime|date|float|decimal|binary|json|jsonb';

function collectNonNullColumnWithoutDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.nonNullColumnWithoutDefault;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const columnCallPattern = new RegExp(
      `\\b(?:t\\.(?:${COLUMN_TYPE_METHODS})|add_column|change_column)\\b`,
      'g',
    );

    for (const callMatch of findAllMatches(stripped, columnCallPattern)) {
      if (callMatch.matchedText.startsWith('t.timestamps') || callMatch.matchedText.startsWith('t.references')) {
        continue;
      }

      if (!/null:\s*false\b/.test(stripped)) {
        continue;
      }

      if (/\bdefault:\s*(?!nil\b)/.test(stripped)) {
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + callMatch.startOffset,
          endOffset: offset + callMatch.endOffset,
          text: callMatch.matchedText,
        }),
      );
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectConsoleOutputInsteadOfLoggerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.consoleOutputInsteadOfLogger,
    appliesTo: 'block',
    pattern: /^\s*(?:puts|print|p|pp)\b[ (]/gm,
  });
}

function collectIncorrectPluralizationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const PLURAL_FORMS =
    'days|hours|minutes|weeks|months|years|seconds|megabytes|gigabytes|kilobytes|bytes';

  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.incorrectPluralization,
    appliesTo: 'block',
    pattern: new RegExp(`\\b1\\.(?:${PLURAL_FORMS})\\b`, 'g'),
  });
}

function collectUsePresenceOverExplicitCheckFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.usePresenceOverExplicitCheck;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /(\w+(?:\.\w+)*)\.present\?\s*\?\s*\1\s*:\s*nil\b/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /(\w+(?:\.\w+)*)\.blank\?\s*\?\s*nil\b\s*:\s*\1/g,
    }),
  );
}

function collectUsePresentToSimplifyConditionalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.usePresentToSimplifyConditional;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /(\w+(?:\.\w+)*)\s*!=\s*nil\b\s*&&\s*!\1\.empty\?/g,
  });
}

function collectRakeTaskMissingEnvironmentFacts(
  text: string,
  detector: string,
  path?: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.rakeTaskMissingEnvironment;

  if (!path || !path.endsWith('.rake')) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const taskMatch = trimmed.match(/^task\s+(?::\w+|['"]\w+['"])\s*(?:=>\s*(\[[^\]]*\]|:?\w+))?(?:\s+do\b|\s*\{)?/);
    if (!taskMatch) {
      offset += line.length + 1;
      continue;
    }

    if (trimmed.match(/task\s+:environment\b/)) {
      offset += line.length + 1;
      continue;
    }

    const depsSection = taskMatch[1];
    let hasEnvironment = false;

    if (depsSection) {
      if (depsSection.startsWith('[')) {
        const depNames = depsSection.slice(1, -1).split(',').map(d => d.trim().replace(/^:/, ''));
        hasEnvironment = depNames.includes('environment');
      } else {
        const depName = depsSection.replace(/^:/, '');
        hasEnvironment = depName === 'environment';
      }
    }

    if (!hasEnvironment) {
      const taskIdx = stripped.indexOf('task');
      if (taskIdx !== -1) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + taskIdx,
            endOffset: offset + taskIdx + 4,
            text: 'task',
          }),
        );
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUseSquareBracketsForAttributesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.useSquareBracketsForAttributes;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bread_attribute\s*\([^)]+\)/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bwrite_attribute\s*\([^,]+,\s*[^)]+\)/g,
    }),
  );
}

function collectRedundantAllowNilFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.redundantAllowNil,
    appliesTo: 'block',
    pattern: /\bvalidates\b.*\ballow_nil:\s*true\b.*\ballow_blank:\s*true\b/g,
  });
}

function collectPlainMethodInsteadOfProcFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const enumerableMethods = 'map|each|select|reject|detect|find|any\\?|all\\?|count|filter|collect|inject|reduce|sort_by|group_by';
  const basePattern = `\\.(?:${enumerableMethods})`;
  const withParens = new RegExp(basePattern + '\\s*\\(\\s*method\\s*\\(', 'g');
  const withoutParens = new RegExp(basePattern + '\\s+method\\s*\\(', 'g');

  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.plainMethodInsteadOfProc,
    appliesTo: 'block',
    pattern: new RegExp(`${basePattern}\\s*(?:\\(\\s*)?method\\s*\\(`, 'g'),
    predicate: (match) => {
      const before = text.slice(0, match.startOffset);
      const lineEnd = text.indexOf('\n', match.startOffset);
      const restOfLine = text.slice(match.startOffset, lineEnd >= 0 ? lineEnd : undefined);
      return !(before + restOfLine).includes('&method(');
    },
  });
}

function collectTimeWithoutZoneFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.timeWithoutZone,
    appliesTo: 'block',
    pattern: /\bTime\.(?:now|parse|current|at|new)\s*(?:\(|(?=\s|$|\.|,|\)|\+|-|\*|\/|&&|\|\|))/g,
    predicate: (match) => {
      const before = text.slice(0, match.startOffset);
      const lineEnd = text.indexOf('\n', match.startOffset);
      const restOfLine = text.slice(match.startOffset, lineEnd >= 0 ? lineEnd : undefined);
      return !/Time\.zone\b/.test(before + restOfLine);
    },
  });
}

function collectInvalidRailsEnvPredicateFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.invalidRailsEnvPredicate;
  const facts: ObservedFact[] = [];
  const validEnvs = new Set(['development', 'test', 'production', 'staging', 'local']);

  for (const match of findAllMatches(text, /\bRails\.env\.(\w+)\?/g)) {
    const envName = match.matchedText.match(/\.(\w+)\?$/)?.[1];
    if (envName && !validEnvs.has(envName)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return facts;
}

function collectOldStyleValidationMacroFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.oldStyleValidationMacro,
    appliesTo: 'block',
    pattern: /\bvalidates_(?:presence|numericality|length|format|inclusion|exclusion|acceptance|confirmation|uniqueness|associated|each)_of\s+/g,
  });
}

const DEPRECATED_FILTER_METHODS =
  'before_filter|after_filter|around_filter|append_before_filter|append_after_filter|append_around_filter|skip_before_filter|skip_after_filter|skip_around_filter|prepend_before_filter|prepend_after_filter|prepend_around_filter';

function collectDeprecatedFilterMethodsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedFilterMethods,
    appliesTo: 'block',
    pattern: new RegExp(`\\b(?:${DEPRECATED_FILTER_METHODS})\\b`, 'g'),
  });
}

function collectActiveRecordAliasFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.activeRecordAlias,
    appliesTo: 'block',
    pattern: /\bupdate_attributes!?\s*\(/g,
  });
}

const AR_OVERRIDE_METHODS =
  'save|save!|create|create!|update|update!|destroy|destroy!|delete|delete_all|reload|touch|increment|increment!|decrement|decrement!|toggle|toggle!|lock!|update_attribute|update_column|update_columns';

function collectActiveRecordMethodOverrideFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.activeRecordMethodOverride;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');

  const classDefs: Array<{ startLine: number; endLine: number }> = [];
  const currentClassStack: Array<{ startLine: number; indent: number }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const indent = line.search(/\S/);
    const stripped = stripHashLineComment(line);

    if (/^\s*class\s+[\w:]+/.test(stripped)) {
      if (
        /<\s*(?:::)?(ActiveRecord::Base|ApplicationRecord)\b/.test(stripped)
      ) {
        currentClassStack.push({ startLine: i, indent: indent >= 0 ? indent : 0 });
      }
    }

    if (/^\s*end\b/.test(stripped) && currentClassStack.length > 0) {
      const last = currentClassStack[currentClassStack.length - 1];
      if (indent <= last.indent) {
        currentClassStack.pop();
        classDefs.push({ startLine: last.startLine, endLine: i });
      }
    }
  }

  const linesToCheck = new Set<number>();
  for (const cd of classDefs) {
    for (let i = cd.startLine + 1; i < cd.endLine; i++) {
      linesToCheck.add(i);
    }
  }

  const overridePattern = new RegExp(
    `^\\s*def\\s+(?:(?:self\\.)?(${AR_OVERRIDE_METHODS})\\b)`,
  );

  for (let i = 0; i < lines.length; i++) {
    if (!linesToCheck.has(i)) continue;

    const line = lines[i];
    const stripped = stripHashLineComment(line);
    const defMatch = stripped.match(overridePattern);

    if (defMatch) {
      const methodName = defMatch[1];
      const lineOffset = lines.slice(0, i).join('\n').length;
      const lineStartOffset = lineOffset > 0 ? lineOffset + 1 : 0;
      const matchIndex = defMatch.index || 0;
      const methodOffsetInLine = stripped.indexOf(methodName, matchIndex);

      if (methodOffsetInLine >= 0) {
        const methodStart = lineStartOffset + methodOffsetInLine;
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: methodStart,
            endOffset: methodStart + methodName.length,
            text: methodName,
          }),
        );
      }
    }
  }

  return facts;
}

function collectActiveSupportAliasFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.activeSupportAlias,
    appliesTo: 'block',
    pattern: /\.(?:starts_with\?|ends_with\?|append|prepend)\s*[(]/g,
  });
}

function collectControllerBaseSubclassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.controllerBaseSubclass,
    appliesTo: 'block',
    pattern: /\bclass\s+\w+\s*<\s*ActionController::Base\b/g,
  });
}

function collectActiveJobBaseSubclassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.activeJobBaseSubclass,
    appliesTo: 'block',
    pattern: /\bclass\s+\w+\s*<\s*ActiveJob::Base\b/g,
  });
}

function collectActionMailerBaseSubclassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.actionMailerBaseSubclass,
    appliesTo: 'block',
    pattern: /\bclass\s+\w+\s*<\s*ActionMailer::Base\b/g,
  });
}

function collectActiveRecordBaseSubclassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.activeRecordBaseSubclass,
    appliesTo: 'block',
    pattern: /\bclass\s+\w+\s*<\s*ActiveRecord::Base\b/g,
  });
}

function collectAssertNotUsageFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.assertNotUsage,
    appliesTo: 'block',
    pattern: /\bassert\s+!/g,
  });
}

function collectDeprecatedBelongsToRequiredFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedBelongsToRequired,
    appliesTo: 'block',
    pattern: /\bbelongs_to\s+:\w+(?:\s*,\s*[^)]*?)?\s*,\s*required:\s*true\b/g,
  });
}

function collectUseBlankSimplifyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.useBlankSimplify,
    appliesTo: 'block',
    pattern: /(\w+(?:\.\w+)*)\.nil\?\s*\|\|\s*\1\.(?:empty|blank)\?/g,
  });
}

function collectAlterQueriesCombineFacts(
  text: string,
  detector: string,
  _path?: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.alterQueriesCombine,
    appliesTo: 'block',
    pattern: /\bchange_column(?:\s+|_|\b)/g,
  });
}

function collectTableWithoutTimestampsFacts(
  text: string,
  detector: string,
  _path?: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.tableWithoutTimestamps;

  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inCreateTable = false;
  let createTableIndent = 0;
  let hasTimestamps = false;
  let createTableStartOffset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (/^create_table\s+/.test(trimmed)) {
      inCreateTable = true;
      createTableIndent = stripped.search(/\S/);
      hasTimestamps = false;
      createTableStartOffset = offset + stripped.search(/\S/);
      offset += line.length + 1;
      continue;
    }

    if (inCreateTable) {
      if (/\.timestamps\b/.test(trimmed)) {
        hasTimestamps = true;
      }

      const lineIndent = stripped.search(/\S/);
      if (lineIndent >= 0 && lineIndent <= createTableIndent && trimmed !== '' && !trimmed.startsWith('#')) {
        inCreateTable = false;
        if (!hasTimestamps) {
          const endIdx = text.indexOf('\n', createTableStartOffset);
          const firstLine = text.slice(createTableStartOffset, endIdx >= 0 ? endIdx : undefined);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: createTableStartOffset,
              endOffset: createTableStartOffset + firstLine.length,
              text: firstLine,
            }),
          );
        }
      }
    }

    offset += line.length + 1;
  }

  if (inCreateTable && !hasTimestamps) {
    const endIdx = text.indexOf('\n', createTableStartOffset);
    const firstLine = text.slice(createTableStartOffset, endIdx >= 0 ? endIdx : undefined);
    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: createTableStartOffset,
        endOffset: createTableStartOffset + firstLine.length,
        text: firstLine,
      }),
    );
  }

  return facts;
}

function collectBadDateUsageFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.badDateUsage,
    appliesTo: 'block',
    pattern: /\bDate\.(?:parse|today|tomorrow|yesterday)\b|\bDateTime\.(?:now|current)\b/g,
    predicate: (match) => {
      const before = text.slice(0, match.startOffset);
      const lineEnd = text.indexOf('\n', match.startOffset);
      const restOfLine = text.slice(match.startOffset, lineEnd >= 0 ? lineEnd : undefined);
      return !/Time\.(?:zone|current)\b/.test(before + restOfLine);
    },
  });
}

function collectUseDelegateFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.useDelegate;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (let i = 0; i < lines.length; i++) {
    const stripped = stripHashLineComment(lines[i]);
    const trimmed = stripped.trim();

    const defMatch = trimmed.match(/^def\s+(\w+)\s*$/);
    if (!defMatch) {
      offset += lines[i].length + 1;
      continue;
    }

    const methodName = defMatch[1];
    const nextLine = i + 1 < lines.length ? stripHashLineComment(lines[i + 1]).trim() : '';

    if (!nextLine) {
      offset += lines[i].length + 1;
      continue;
    }

    if (nextLine.startsWith('#')) {
      offset += lines[i].length + 1;
      continue;
    }

    const delegationMatch = nextLine.match(
      /^(?:@(\w+)\.|(\w+)\.)(\w+)(?:\s*\([^)]*\))?\s*$/,
    );
    if (!delegationMatch) {
      offset += lines[i].length + 1;
      continue;
    }

    const calledMethod = delegationMatch[3];
    if (calledMethod !== methodName) {
      offset += lines[i].length + 1;
      continue;
    }

    const defLineStart = offset + stripped.search(/\S/);
    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'function',
        kind,
        startOffset: defLineStart,
        endOffset: defLineStart + methodName.length,
        text: methodName,
      }),
    );

    offset += lines[i].length + 1;
  }

  return facts;
}

function collectAllowBlankWithDelegateFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.allowBlankWithDelegate,
    appliesTo: 'block',
    pattern: /\bdelegate\s+(?::\w+(?:\s*,\s*)?)+(?:.*\b)allow_blank:\s*true\b/g,
  });
}

function collectAllEachToFindEachFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.allEachToFindEach,
    appliesTo: 'block',
    pattern: /\b(?:all|where\([^)]*\))\.each\s*(?:do\b|\{)/g,
  });
}

function collectDeprecatedFindByDynamicFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.deprecatedFindByDynamic,
    appliesTo: 'block',
    pattern: /\bfind_by_[a-z_]\w*\s*\(/g,
    predicate: (match) => !match.matchedText.startsWith('find_by_sql'),
  });
}

function collectEnumArraySyntaxFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.enumArraySyntax,
    appliesTo: 'block',
    pattern: /\benum\s+:(\w+)\s*,\s*\[/g,
  });
}

function collectEnumDuplicateValuesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.enumDuplicateValues;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const enumMatch = stripped.match(/\benum\s+(\w+)\s*:\s*\{([^}]*)\}/);

    if (enumMatch) {
      const hashContent = enumMatch[2];
      const valuePairs = hashContent.split(',').map(p => p.trim()).filter(Boolean);
      const seenValues = new Set<string>();

      for (const pair of valuePairs) {
        const kvMatch = pair.match(/(\w+)\s*:\s*(-?\d+(?:\.\d+)?)/);
        if (!kvMatch) continue;

        const value = kvMatch[2];
        if (seenValues.has(value)) {
          const idx = stripped.indexOf(kvMatch[0]);
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: offset + (idx >= 0 ? idx : 0),
              endOffset: offset + (idx >= 0 ? idx + kvMatch[0].length : 0),
              text: kvMatch[0],
            }),
          );
        } else {
          seenValues.add(value);
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectExitInAppCodeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.exitInAppCode,
    appliesTo: 'block',
    pattern: /\bexit[!]?\b(?!\s*\.\s*\w)/g,
    predicate: (match) => {
      const lineStart = text.lastIndexOf('\n', match.startOffset) + 1;
      const lineEnd = text.indexOf('\n', match.startOffset);
      const line = text.slice(lineStart, lineEnd >= 0 ? lineEnd : undefined);
      const hashIndex = line.indexOf('#');
      if (hashIndex >= 0 && match.startOffset > lineStart + hashIndex) {
        return false;
      }
      const charBefore = text[match.startOffset - 1];
      if (charBefore === "'" || charBefore === '"') {
        return false;
      }
      const linePrefix = line.slice(0, match.startOffset - lineStart).trimStart();
      return !/^(def|when|class|module|desc)\s/.test(linePrefix);
    },
  });
}

function collectRailsEnvEqualityFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.railsEnvEquality,
    appliesTo: 'block',
    pattern: /\bRails\.env\s*(==|!=|\.eql\?\(|\.equal\?\(|\.include\?\(|\.(?:is_a|kind_of)\?\(|\.in\?\()/g,
  });
}

function collectRailsRootJoinFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.railsRootJoin;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bRails\.root\s*\.to_s\s*\+/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bRails\.root\s*\+\s*['"]/g,
    }),
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bFile\.join\s*\(\s*Rails\.root\b/g,
    }),
  );
}

const HTTP_STATUS_SYMBOLS =
  'ok|created|accepted|no_content|moved_permanently|found|see_other|not_modified|bad_request|unauthorized|forbidden|not_found|unprocessable_entity|internal_server_error|service_unavailable';

function collectHasAndBelongsToManyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.hasAndBelongsToMany,
    appliesTo: 'block',
    pattern: /\bhas_and_belongs_to_many\s+:\w+/g,
  });
}

function collectDependentOptionCascadeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.dependentOptionCascade;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const assocMatch = stripped.match(
      /\b(?:has_many|has_one|belongs_to)\s+:\w+\b/,
    );
    if (assocMatch && /\bdependent\s*:\s*:/.test(stripped)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: offset + assocMatch.index!,
          endOffset: offset + assocMatch.index! + assocMatch[0].length,
          text: assocMatch[0],
        }),
      );
    }
    offset += line.length + 1;
  }

  return facts;
}

function collectHelperInstanceVariablesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.helperInstanceVariables;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const moduleIndents: number[] = [];

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const moduleMatch = trimmed.match(/^module\s+(?:\w*::)*\w+Helper\b/);
    if (moduleMatch) {
      moduleIndents.push(stripped.search(/\S/));
      offset += line.length + 1;
      continue;
    }

    if (moduleIndents.length > 0 && trimmed === 'end') {
      const currentIndent = stripped.search(/\S/);
      if (currentIndent === moduleIndents[moduleIndents.length - 1]) {
        moduleIndents.pop();
      }
      offset += line.length + 1;
      continue;
    }

    if (moduleIndents.length > 0) {
      const ivarMatch = trimmed.match(/@\w+/);
      if (ivarMatch) {
        const atIndex = stripped.indexOf('@');
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + atIndex,
            endOffset: offset + atIndex + ivarMatch[0].length,
            text: ivarMatch[0],
          }),
        );
      }
    }
    offset += line.length + 1;
  }

  return facts;
}

function collectHttpMethodsWithoutParamsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.httpMethodsWithoutParams;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  const methodPattern = /\b(?:get|post|put|patch|delete|head)\s+:\w+/;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const match = stripped.match(methodPattern);
    if (match) {
      const afterAction = stripped.slice(match.index! + match[0].length).trim();
      if (!afterAction.startsWith(',') && !afterAction.startsWith('(')) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: offset + match.index!,
            endOffset: offset + match.index! + match[0].length,
            text: match[0],
          }),
        );
      }
    }
    offset += line.length + 1;
  }

  return facts;
}

function collectDeprecatedHttpStatusSymbolsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.deprecatedHttpStatusSymbols;
  const statusSymbolPattern = new RegExp(
    `\\bstatus:\\s*:(${HTTP_STATUS_SYMBOLS})\\b`,
    'g',
  );
  const headSymbolPattern = new RegExp(
    `\\bhead\\s+:(${HTTP_STATUS_SYMBOLS})\\b`,
    'g',
  );

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: statusSymbolPattern,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: headSymbolPattern,
    }),
  );
}

function collectSkipFilterConditionalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.skipFilterConditional;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inSkipCall = false;
  let callText = '';
  let callFirstLineStart = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (!inSkipCall) {
      const skipMatch = trimmed.match(
        /^(skip_before_action|skip_after_action|skip_around_action)\b/,
      );
      if (skipMatch) {
        inSkipCall = true;
        callFirstLineStart = offset + stripped.search(/\S/);
        callText = stripped;
        if (!trimmed.endsWith(',') && !trimmed.endsWith('\\')) {
          inSkipCall = false;
          const hasOnlyExcept = /\b(?:only|except)\s*:/.test(callText);
          const hasIfUnless = /\b(?:if|unless)\s*:/.test(callText);
          if (hasOnlyExcept && hasIfUnless) {
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'block',
                kind,
                startOffset: callFirstLineStart,
                endOffset: callFirstLineStart + stripped.trimEnd().length,
                text: trimmed,
              }),
            );
          }
        }
      }
    } else {
      callText += '\n' + stripped;
      if (!trimmed.endsWith(',') && !trimmed.endsWith('\\')) {
        inSkipCall = false;
        const hasOnlyExcept = /\b(?:only|except)\s*:/.test(callText);
        const hasIfUnless = /\b(?:if|unless)\s*:/.test(callText);
        if (hasOnlyExcept && hasIfUnless) {
          const firstLine = callText.split('\n')[0];
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: callFirstLineStart,
              endOffset: callFirstLineStart + firstLine.trimEnd().length,
              text: firstLine.trim(),
            }),
          );
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectMissingInverseOfFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.missingInverseOf;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inAssociation = false;
  let assocText = '';
  let assocFirstLineStart = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    if (!inAssociation) {
      const assocMatch = trimmed.match(/^(has_many|belongs_to|has_one)\s+:\w+\b/);
      if (assocMatch) {
        inAssociation = true;
        assocFirstLineStart = offset + stripped.search(/\S/);
        assocText = stripped;
        if (!trimmed.endsWith(',') && !trimmed.endsWith('\\')) {
          inAssociation = false;
          if (!/\binverse_of\s*:/.test(assocText)) {
            facts.push(
              createOffsetFact(text, {
                detector,
                appliesTo: 'block',
                kind,
                startOffset: assocFirstLineStart,
                endOffset: assocFirstLineStart + stripped.trimEnd().length,
                text: trimmed,
              }),
            );
          }
        }
      }
    } else {
      assocText += '\n' + stripped;
      if (!trimmed.endsWith(',') && !trimmed.endsWith('\\')) {
        inAssociation = false;
        if (!/\binverse_of\s*:/.test(assocText)) {
          facts.push(
            createOffsetFact(text, {
              detector,
              appliesTo: 'block',
              kind,
              startOffset: assocFirstLineStart,
              endOffset: assocFirstLineStart + assocText.split('\n')[0].trimEnd().length,
              text: assocText.split('\n')[0].trim(),
            }),
          );
        }
      }
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectUndefinedActionFilterFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.undefinedActionFilter;
  const facts: ObservedFact[] = [];
  const definedMethods = new Set<string>();
  const beforeActions: {
    name: string;
    startOffset: number;
    length: number;
    text: string;
  }[] = [];
  const lines = text.split('\n');
  let offset = 0;

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const defMatch = trimmed.match(/^def\s+(\w+)/);
    if (defMatch) {
      definedMethods.add(defMatch[1]);
    }

    const baMatch = trimmed.match(/^before_action\s+:(\w+)/);
    if (baMatch) {
      const idx = stripped.indexOf(baMatch[0]);
      beforeActions.push({
        name: baMatch[1],
        startOffset: offset + idx,
        length: baMatch[0].length,
        text: baMatch[0],
      });
    }

    offset += line.length + 1;
  }

  for (const ba of beforeActions) {
    if (!definedMethods.has(ba.name)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: ba.startOffset,
          endOffset: ba.startOffset + ba.length,
          text: ba.text,
        }),
      );
    }
  }

  return facts;
}

function collectWhereFirstOverFindByFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.whereFirstOverFindBy,
    appliesTo: 'block',
    pattern: /\b[A-Z]\w*\.find_by\s*\(/g,
    predicate: (match) => !match.matchedText.startsWith('find_by_sql'),
  });
}

function collectRedundantWithOptionsReceiverFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.redundantWithOptionsReceiver;
  const facts: ObservedFact[] = [];
  const lines = text.split('\n');
  let offset = 0;
  let inWithOptionsBlock = false;
  let blockVarName = '';

  for (const line of lines) {
    const stripped = stripHashLineComment(line);
    const trimmed = stripped.trim();

    const woMatch = trimmed.match(/^with_options\s+.*\s+do\s+\|(\w+)\|/);
    if (woMatch) {
      inWithOptionsBlock = true;
      blockVarName = woMatch[1];
      offset += line.length + 1;
      continue;
    }

    const endMatch = trimmed.match(/^end\b/);
    if (endMatch && inWithOptionsBlock) {
      inWithOptionsBlock = false;
      blockVarName = '';
      offset += line.length + 1;
      continue;
    }

    if (inWithOptionsBlock && blockVarName) {
      const receiverPattern = new RegExp(
        `\\b${blockVarName}\\.(?:has_many|has_one|belongs_to|has_and_belongs_to_many|validate|validates|scope|default_scope)\\b`,
        'g',
      );
      for (const match of findAllMatches(stripped, receiverPattern)) {
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
    }

    offset += line.length + 1;
  }

  return facts;
}

function collectClassNameShouldBeStringFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.classNameShouldBeString,
    appliesTo: 'block',
    pattern: /\bclass_name:\s*[A-Z]\w*(?:\s*\.\s*\w+)*(?:::[A-Z]\w*)*\b(?!\s*:)/g,
    predicate: (match) => {
      const val = match.matchedText.replace(/^class_name:\s*/, '');
      return !/^['"]/.test(val) && !/^(nil|true|false)\b/.test(val);
    },
  });
}

function collectNonPreferredAssertFalsenessFacts(
  text: string,
  detector: string,
  path?: string,
): ObservedFact[] {
  if (path && !path.includes('test/') && !path.includes('specs/') && !path.includes('_test.rb') && !path.includes('_spec.rb') && !path.includes('/spec/')) {
    return [];
  }
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.nonPreferredAssertFalseness,
    appliesTo: 'block',
    pattern: /\brefute\b/g,
  });
}

function collectRelativeDateAsConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.relativeDateAsConstant,
    appliesTo: 'block',
    pattern: /\b[A-Z][A-Z_]{1,}\s*=\s*.+\.(?:today|now|since|ago|from_now|beginning_of_day|end_of_day)\b/g,
  });
}

function collectInconsistentRequestReferrerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_BUG_RISK_FACT_KINDS.inconsistentRequestReferrer;
  const facts: ObservedFact[] = [];
  for (const match of findAllMatches(text, /\brequest\.referrer\b/g)) {
    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }
  return facts;
}

function collectInconsistentSafeNavigationTryFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.inconsistentSafeNavigationTry,
    appliesTo: 'block',
    pattern: /\.try!\(/g,
  });
}

function collectSafeNavigationWithBlankFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_BUG_RISK_FACT_KINDS.safeNavigationWithBlank,
    appliesTo: 'block',
    pattern: /&\.blank\?/g,
  });
}
