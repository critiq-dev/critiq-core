import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  isPropertyNamed,
  looksSensitiveIdentifier,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  collectSensitiveSignals,
  isRequestDerivedExpression,
} from './analysis';
import {
  FACT_KINDS,
  dynamodbQueryCommandNames,
  fileWriteSinkNames,
  sensitiveComparePattern,
} from './constants';
import { normalizeText } from './text-normalization';

export function collectNosqlInjectionFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  modelNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  const isSanitized = (
    node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  ) =>
    node?.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    isPropertyNamed(node.callee.property, 'toString');

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      return;
    }

    if (node.type === 'NewExpression') {
      if (
        node.callee.type !== 'Identifier' ||
        !modelNames.has(node.callee.name)
      ) {
        return;
      }

      const argument = node.arguments[0];

      if (
        !argument ||
        argument.type === 'SpreadElement' ||
        isSanitized(argument) ||
        !isRequestDerivedExpression(argument, taintedNames, context.sourceText)
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.nosqlInjection,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: node.callee.name,
          },
          text: node.callee.name,
        }),
      );

      return;
    }

    if (
      node.callee.type !== 'MemberExpression' ||
      node.callee.object.type !== 'Identifier'
    ) {
      return;
    }

    const objectName = node.callee.object.name;

    if (!modelNames.has(objectName)) {
      return;
    }

    const methodName = getNodeText(node.callee.property, context.sourceText);

    if (
      !methodName ||
      !/^(find|delete|update|replace|where|create|insert|map|bulk|aggregate|count)/iu.test(
        methodName,
      )
    ) {
      return;
    }

    const hasUnsafeArgument = node.arguments.some(
      (argument) =>
        argument.type !== 'SpreadElement' &&
        !isSanitized(argument) &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText),
    );

    if (!hasUnsafeArgument) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.nosqlInjection,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: `${objectName}.${methodName}`,
        },
        text: `${objectName}.${methodName}`,
      }),
    );
  });

  return facts;
}

export function collectDynamodbQueryFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  dynamodbClientNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'NewExpression') {
      const calleeText = getNodeText(node.callee, context.sourceText);
      const argument = node.arguments[0];

      if (
        calleeText &&
        dynamodbQueryCommandNames.has(calleeText) &&
        argument &&
        argument.type !== 'SpreadElement' &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.dynamodbQueryInjection,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }

      return;
    }

    if (
      node.type !== 'CallExpression' ||
      node.callee.type !== 'MemberExpression'
    ) {
      return;
    }

    if (node.callee.object.type !== 'Identifier') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      !calleeText ||
      !dynamodbClientNames.has(node.callee.object.name) ||
      !/\.(?:query|scan)$/u.test(calleeText)
    ) {
      return;
    }

    const argument = node.arguments[0];

    if (
      !argument ||
      argument.type === 'SpreadElement' ||
      !isRequestDerivedExpression(argument, taintedNames, context.sourceText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.dynamodbQueryInjection,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

export function collectFileAndExceptionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (calleeText && fileWriteSinkNames.has(calleeText)) {
        const payload = node.arguments[1];

        if (payload && payload.type !== 'SpreadElement') {
          const sensitiveSignals = collectSensitiveSignals(
            payload,
            context.sourceText,
          );

          if (sensitiveSignals.length > 0) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.sensitiveDataWrittenToFile,
                node,
                nodeIds: context.nodeIds,
                props: {
                  sensitiveSignals,
                  sink: calleeText,
                },
                text: calleeText,
              }),
            );
          }
        }
      }

      if (
        calleeText === 'Promise.reject' ||
        (node.callee.type === 'Identifier' && node.callee.name === 'reject')
      ) {
        const sensitiveSignals = collectSensitiveSignals(
          node.arguments[0] as TSESTree.Expression | undefined,
          context.sourceText,
        );

        if (sensitiveSignals.length > 0) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.sensitiveDataInException,
              node,
              nodeIds: context.nodeIds,
              props: {
                sensitiveSignals,
                sink: calleeText ?? 'reject',
              },
              text: calleeText ?? 'reject',
            }),
          );
        }
      }

      return;
    }

    if (node.type === 'ThrowStatement') {
      const sensitiveSignals = collectSensitiveSignals(
        node.argument,
        context.sourceText,
      );

      if (sensitiveSignals.length > 0) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.sensitiveDataInException,
            node,
            nodeIds: context.nodeIds,
            props: {
              sensitiveSignals,
              sink: 'throw',
            },
            text: 'throw',
          }),
        );
      }
    }
  });

  return facts;
}

function containsBitmaskOperator(node: TSESTree.Node): boolean {
  let found = false;

  walkAst(node, (inner) => {
    if (found) {
      return;
    }

    if (
      inner.type === 'BinaryExpression' &&
      (inner.operator === '|' || inner.operator === '&' || inner.operator === '^')
    ) {
      found = true;
    }
  });

  return found;
}

export function collectObservableTimingFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'BinaryExpression' ||
      !['==', '===', '!=', '!=='].includes(node.operator)
    ) {
      return;
    }

    const leftText = normalizeText(getNodeText(node.left, context.sourceText));
    const rightText = normalizeText(
      getNodeText(node.right, context.sourceText),
    );

    const secretSide =
      sensitiveComparePattern.test(leftText) ||
      looksSensitiveIdentifier(leftText)
        ? leftText
        : sensitiveComparePattern.test(rightText) ||
            looksSensitiveIdentifier(rightText)
          ? rightText
          : undefined;

    const otherSide = secretSide === leftText ? rightText : leftText;

    if (!secretSide || /^(null|undefined)$/u.test(otherSide)) {
      return;
    }

    // Exclude comparisons where either operand is a numeric literal
    if (
      (node.left.type === 'Literal' && typeof node.left.value === 'number') ||
      (node.right.type === 'Literal' && typeof node.right.value === 'number')
    ) {
      return;
    }

    // Exclude comparisons where the left operand is a typeof check
    // (e.g. typeof x === 'string'), which doesn't leak timing.
    if (
      node.left.type === 'UnaryExpression' &&
      node.left.operator === 'typeof'
    ) {
      return;
    }

    // Exclude comparisons involving bitmask composition (|, &, ^),
    // since these are constant-time operations unrelated to string comparison.
    if (containsBitmaskOperator(node.left) || containsBitmaskOperator(node.right)) {
      return;
    }

    // Exclude SCREAMING_SNAKE_CASE constants (e.g. HASH_UNDEFINED,
    // WRAP_BIND_FLAG) whose names happen to contain sensitive substrings.
    // These are bitmask / flag / enum constants, not actual secrets.
    const secretNode = secretSide === leftText ? node.left : node.right;
    if (
      secretNode.type === 'Identifier' &&
      /^[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)+$/.test(secretNode.name)
    ) {
      return;
    }

    // Exclude comparisons involving a MemberExpression with a PascalCase
    // property name (e.g. SyntaxKind.ExclamationToken, NodeType.CallExpression).
    // PascalCase member properties are enum/namespace constant accesses,
    // not runtime secret values.
    if (
      (node.left.type === 'MemberExpression' &&
        node.left.property.type === 'Identifier' &&
        /^[A-Z]/.test(node.left.property.name)) ||
      (node.right.type === 'MemberExpression' &&
        node.right.property.type === 'Identifier' &&
        /^[A-Z]/.test(node.right.property.name))
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.observableTimingDiscrepancy,
        node,
        nodeIds: context.nodeIds,
        props: {
          comparedValue: secretSide,
          operator: node.operator,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}
