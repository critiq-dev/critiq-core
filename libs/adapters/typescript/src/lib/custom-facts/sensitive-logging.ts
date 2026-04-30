import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectPrivacyDatatypes } from './privacy-vocabulary';
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
  arguments_: readonly (
    | import('@typescript-eslint/typescript-estree').TSESTree.CallExpressionArgument
  )[],
  sourceText: string,
): string[] {
  const labels: string[] = [];

  for (const argument of arguments_) {
    for (const label of collectPrivacyDatatypes(argument, sourceText)) {
      if (!labels.includes(label)) {
        labels.push(label);
      }
    }
  }

  return labels;
}
