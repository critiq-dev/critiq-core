import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectRequestDerivedNames,
  collectValidatedTrustBoundaryState,
  isRequestDerivedExpression,
  isValidatedTrustBoundaryExpression,
} from './additional-public-security/analysis';
import { FACT_KINDS } from './additional-public-security/constants';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAstWithAncestors,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

function isLoopNode(node: TSESTree.Node): boolean {
  return (
    node.type === 'ForStatement' ||
    node.type === 'ForInStatement' ||
    node.type === 'ForOfStatement' ||
    node.type === 'WhileStatement' ||
    node.type === 'DoWhileStatement'
  );
}

function hasLoopAncestor(
  node: TSESTree.Node,
  parents: readonly TSESTree.Node[],
): boolean {
  if (isLoopNode(node)) {
    return true;
  }

  return parents.some((parent) => isLoopNode(parent));
}

function isUserControlledRegexpPattern(
  expression: TSESTree.Expression | TSESTree.SpreadElement | undefined,
  taintedNames: ReadonlySet<string>,
  validatedTrustBoundaries: ReturnType<typeof collectValidatedTrustBoundaryState>,
  sourceText: string,
): boolean {
  if (!expression || expression.type === 'SpreadElement') {
    return false;
  }

  if (
    isValidatedTrustBoundaryExpression(
      expression,
      validatedTrustBoundaries,
      sourceText,
    )
  ) {
    return false;
  }

  return isRequestDerivedExpression(expression, taintedNames, sourceText);
}

function collectRegexpFactsInScope(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  validatedTrustBoundaries: ReturnType<typeof collectValidatedTrustBoundaryState>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (hasLoopAncestor(node, ancestors)) {
      return;
    }

    if (node.type === 'NewExpression') {
      if (
        node.callee.type !== 'Identifier' ||
        node.callee.name !== 'RegExp' ||
        !isUserControlledRegexpPattern(
          node.arguments[0],
          taintedNames,
          validatedTrustBoundaries,
          context.sourceText,
        )
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.userControlledRegexp,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: 'RegExp',
          },
          text: getNodeText(node, context.sourceText),
        }),
      );

      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      calleeText !== 'RegExp' ||
      !isUserControlledRegexpPattern(
        node.arguments[0],
        taintedNames,
        validatedTrustBoundaries,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.userControlledRegexp,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

export const collectUserControlledRegexpFacts: TypeScriptFactDetector = (
  context,
) => {
  const taintedNames = collectRequestDerivedNames(context);
  const validatedTrustBoundaries = collectValidatedTrustBoundaryState(context);

  return collectRegexpFactsInScope(
    context,
    taintedNames,
    validatedTrustBoundaries,
  );
};
