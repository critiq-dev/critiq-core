import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';

const FACT_KIND = 'security.sensitive-data-in-logs-and-telemetry';

const sensitiveSinkPattern =
  /(^|\.)(console\.(warn|info)|logger\.(warn|info)|captureException|captureMessage|recordException|track|identify|logEvent|setAttribute|setAttributes|setUser)$/u;

const redactionWrapperPattern =
  /(^|\.)(redact|mask|sanitize|anonymize|dropSensitiveFields|omitSensitiveFields|redactSensitive|safeSerialize|hashSensitiveValue)$/u;

const sensitiveLabelOrder = [
  'email',
  'phone',
  'address',
  'dob',
  'ssn',
  'token',
  'jwt',
  'secret',
  'password',
  'session',
  'cookie',
  'auth',
  'card',
] as const;

export function collectSensitiveLoggingFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !sensitiveSinkPattern.test(calleeText)) {
      return;
    }

    const sensitiveLabels = collectSensitiveLabelsFromArguments(
      node.arguments,
      context.sourceText,
    );

    if (sensitiveLabels.length === 0) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        text: getNodeText(node, context.sourceText),
        props: {
          sink: calleeText,
          datatype: sensitiveLabels[0],
          sensitiveLabels,
        },
      }),
    );
  });

  return facts;
}

function collectSensitiveLabelsFromArguments(
  arguments_: TSESTree.CallExpressionArgument[],
  sourceText: string,
): string[] {
  const labels: string[] = [];

  for (const argument of arguments_) {
    for (const label of collectSensitiveLabelsFromNode(argument, sourceText)) {
      if (!labels.includes(label)) {
        labels.push(label);
      }
    }
  }

  return labels;
}

function collectSensitiveLabelsFromNode(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string[] {
  if (!node) {
    return [];
  }

  switch (node.type) {
    case 'Identifier':
      return collectSensitiveLabelFromText(node.name);
    case 'Literal':
      return typeof node.value === 'string'
        ? collectSensitiveLabelFromText(node.value)
        : [];
    case 'MemberExpression':
      return uniqueLabels([
        ...collectSensitiveLabelsFromNode(node.object, sourceText),
        ...collectSensitiveLabelsFromNode(node.property, sourceText),
        ...collectSensitiveLabelFromText(getNodeText(node.property, sourceText)),
      ]);
    case 'Property':
      return uniqueLabels([
        ...collectSensitiveLabelsFromNode(node.key as TSESTree.Node, sourceText),
        ...collectSensitiveLabelsFromNode(node.value as TSESTree.Node, sourceText),
      ]);
    case 'ObjectExpression':
      return uniqueLabels(
        node.properties.flatMap((property) =>
          property.type === 'Property'
            ? collectSensitiveLabelsFromNode(property, sourceText)
            : collectSensitiveLabelsFromNode(property.argument, sourceText),
        ),
      );
    case 'ArrayExpression':
      return uniqueLabels(
        node.elements.flatMap((element) =>
          element ? collectSensitiveLabelsFromNode(element, sourceText) : [],
        ),
      );
    case 'TemplateLiteral':
      return uniqueLabels(
        node.expressions.flatMap((expression) =>
          collectSensitiveLabelsFromNode(expression, sourceText),
        ),
      );
    case 'CallExpression': {
      const calleeText = getCalleeText(node.callee, sourceText);

      if (calleeText && redactionWrapperPattern.test(calleeText)) {
        return [];
      }

      return uniqueLabels(
        node.arguments.flatMap((argument) =>
          collectSensitiveLabelsFromNode(argument, sourceText),
        ),
      );
    }
    case 'BinaryExpression':
    case 'LogicalExpression':
      return uniqueLabels([
        ...collectSensitiveLabelsFromNode(node.left, sourceText),
        ...collectSensitiveLabelsFromNode(node.right, sourceText),
      ]);
    case 'ConditionalExpression':
      return uniqueLabels([
        ...collectSensitiveLabelsFromNode(node.test, sourceText),
        ...collectSensitiveLabelsFromNode(node.consequent, sourceText),
        ...collectSensitiveLabelsFromNode(node.alternate, sourceText),
      ]);
    case 'AwaitExpression':
      return collectSensitiveLabelsFromNode(node.argument, sourceText);
    case 'ChainExpression':
      return collectSensitiveLabelsFromNode(node.expression, sourceText);
    case 'UnaryExpression':
      return collectSensitiveLabelsFromNode(node.argument, sourceText);
    case 'TSAsExpression':
      return collectSensitiveLabelsFromNode(node.expression, sourceText);
    case 'TSTypeAssertion':
      return collectSensitiveLabelsFromNode(node.expression, sourceText);
    case 'SpreadElement':
      return collectSensitiveLabelsFromNode(node.argument, sourceText);
    default:
      return [];
  }
}

function collectSensitiveLabelFromText(text: string | undefined): string[] {
  if (!text) {
    return [];
  }

  const normalized = text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[^a-z0-9]+/gi, ' ')
    .toLowerCase();

  for (const label of sensitiveLabelOrder) {
    const tokenPattern = new RegExp(`(^|\\s)${label}(\\s|$)`, 'u');

    if (tokenPattern.test(normalized)) {
      return [label];
    }
  }

  return [];
}

function uniqueLabels(labels: string[]): string[] {
  const unique: string[] = [];

  for (const label of labels) {
    if (!unique.includes(label)) {
      unique.push(label);
    }
  }

  return unique;
}

