import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  isBooleanLiteral,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { objectPropertyNames } from './object-flags';

function propertyExpressionValue(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
): TSESTree.Expression | undefined {
  const property = getObjectProperty(objectExpression, name);

  return property?.value as TSESTree.Expression | undefined;
}

function ajvOptionsAreStrict(
  objectExpression: TSESTree.ObjectExpression | undefined,
): boolean {
  if (!objectExpression) {
    return false;
  }

  const names = objectPropertyNames(objectExpression);

  if (
    names.has('strict') &&
    isBooleanLiteral(propertyExpressionValue(objectExpression, 'strict'), true)
  ) {
    return true;
  }

  if (
    names.has('strictTypes') &&
    isBooleanLiteral(
      propertyExpressionValue(objectExpression, 'strictTypes'),
      true,
    )
  ) {
    return true;
  }

  if (
    names.has('strictSchema') &&
    isBooleanLiteral(
      propertyExpressionValue(objectExpression, 'strictSchema'),
      true,
    )
  ) {
    return true;
  }

  return false;
}

/** Flags `ajv` instances compiled with `allErrors: true` without strict-mode hardening. */
export function collectAjvInsecureConfigurationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);

  walkAst(context.program, (node) => {
    if (node.type !== 'NewExpression' && node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'Ajv' && calleeText !== 'Ajv.default') {
      return;
    }

    const firstArgument = node.arguments[0] as TSESTree.Expression | undefined;
    const options = resolveObjectExpression(firstArgument, objectBindings);

    if (!options) {
      return;
    }

    if (!isBooleanLiteral(propertyExpressionValue(options, 'allErrors'), true)) {
      return;
    }

    if (ajvOptionsAreStrict(options)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.ajvInsecureConfiguration,
        node,
        nodeIds: context.nodeIds,
        text: getNodeText(node, context.sourceText) ?? calleeText,
      }),
    );
  });

  return facts;
}
