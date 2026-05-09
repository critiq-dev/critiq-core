import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { isRequestDerivedExpression } from './analysis';
import { FACT_KINDS } from './constants';

// Recognize the broader Node.js logger families that the existing
// `format-string-using-user-input` rule does not cover. The format-string rule
// already handles `console|logger|log.<level>` and `util.format(WithOptions)`,
// so we focus log-injection on pino, winston, bunyan, and consola here to
// avoid duplicate findings on identical call shapes.
const broaderLoggerSinkPattern =
  /^(?:pino|winston|bunyan|consola)\.(?:debug|error|info|log|warn|trace)$/u;

// Sanitizers that neutralize CRLF / control-character injection or escape the
// payload before it reaches the log sink. Wrapping a tainted value with one
// of these is the recommended remediation, so wrapped expressions are not
// flagged.
const sanitizerCalleePattern =
  /^(?:JSON\.stringify|encodeURIComponent|querystring\.escape|escape)$/u;

function isCrlfStrippingReplaceCall(
  node: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const calleeText = getCalleeText(node.callee, sourceText);

  if (!calleeText || !/(^|\.)replace$/u.test(calleeText)) {
    return false;
  }

  const firstArgument = node.arguments[0];

  if (!firstArgument) {
    return false;
  }

  const argumentText = getNodeText(firstArgument, sourceText) ?? '';

  // Crude but deterministic: any replace whose pattern mentions \r, \n, the
  // escaped variants, or a CRLF/whitespace character class is treated as a
  // log-injection sanitizer.
  return /(?:\\r|\\n|\\s|\[\^?\\r|\[\^?\\n)/u.test(argumentText);
}

function isSanitizerCall(
  node: TSESTree.Node,
  sourceText: string,
): boolean {
  if (node.type !== 'CallExpression') {
    return false;
  }

  const calleeText = getCalleeText(node.callee, sourceText);

  if (calleeText && sanitizerCalleePattern.test(calleeText)) {
    return true;
  }

  return isCrlfStrippingReplaceCall(node, sourceText);
}

// Returns true when `node` embeds an unsanitized request-derived value into a
// log message via interpolation, `+` concatenation, or a direct identifier
// reference. Plain object expressions are treated as structured logging and
// ignored, since CRLF injection requires the tainted value to be part of the
// rendered message text.
function containsUnsanitizedTaintedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'CallExpression' && isSanitizerCall(node, sourceText)) {
    return false;
  }

  if (node.type === 'ObjectExpression') {
    return false;
  }

  if (node.type === 'TemplateLiteral') {
    return node.expressions.some((expression) => {
      if (
        expression.type === 'CallExpression' &&
        isSanitizerCall(expression, sourceText)
      ) {
        return false;
      }

      return isRequestDerivedExpression(
        expression,
        taintedNames,
        sourceText,
      );
    });
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return (
      containsUnsanitizedTaintedExpression(
        node.left,
        taintedNames,
        sourceText,
      ) ||
      containsUnsanitizedTaintedExpression(
        node.right,
        taintedNames,
        sourceText,
      )
    );
  }

  if (
    node.type === 'Identifier' ||
    node.type === 'MemberExpression' ||
    node.type === 'ChainExpression' ||
    node.type === 'TSAsExpression' ||
    node.type === 'TSTypeAssertion'
  ) {
    return isRequestDerivedExpression(node, taintedNames, sourceText);
  }

  return false;
}

function getMessageArgument(
  node: TSESTree.CallExpression,
  calleeText: string,
): TSESTree.Expression | undefined {
  // `winston.log(level, message, ...)` puts the message in position 1; every
  // other recognized sink uses position 0.
  const messageIndex = calleeText === 'winston.log' ? 1 : 0;
  const messageArgument = node.arguments[messageIndex];

  if (!messageArgument || messageArgument.type === 'SpreadElement') {
    return undefined;
  }

  return messageArgument;
}

/**
 * Collects log-injection facts where request-derived data is interpolated or
 * concatenated into a logger message without an obvious CRLF/control-character
 * sanitizer. Targets the broader Node.js logger families (pino, winston,
 * bunyan, consola) that fall outside the existing format-string rule.
 */
export function collectLogInjectionFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !broaderLoggerSinkPattern.test(calleeText)) {
      return;
    }

    const messageArgument = getMessageArgument(node, calleeText);

    if (
      !messageArgument ||
      !containsUnsanitizedTaintedExpression(
        messageArgument,
        taintedNames,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.logInjection,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}
