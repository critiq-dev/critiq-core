import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import {
  findInnermostEnclosingFunction,
  getFirstParamPropBindings,
} from './function-context';

const FACT_DERIVED_STATE = 'ui.react.derived-state-from-props';

function expressionUsesPropsMember(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
): boolean {
  let uses = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (
      !uses &&
      node.type === 'MemberExpression' &&
      node.object.type === 'Identifier' &&
      node.object.name === 'props'
    ) {
      uses = true;
    }
  });

  return uses;
}

function expressionUsesAnyIdentifier(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
  names: ReadonlySet<string>,
): boolean {
  let uses = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (!uses && node.type === 'Identifier' && names.has(node.name)) {
      uses = true;
    }
  });

  return uses;
}

/** Detects React state initialized directly from props. */
export function collectDerivedStateFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'useState' && calleeText !== 'React.useState') {
      return;
    }

    const rawInit = node.arguments[0];

    if (!rawInit || rawInit.type === 'SpreadElement') {
      return;
    }

    const init = rawInit as TSESTree.Expression;
    const enclosing = findInnermostEnclosingFunction(context.program, node);

    if (!enclosing) {
      return;
    }

    const bindings = getFirstParamPropBindings(enclosing);

    if (!bindings) {
      return;
    }

    const isDerived =
      (bindings.hasPropsParam && expressionUsesPropsMember(init)) ||
      (!bindings.hasPropsParam &&
        bindings.propNames.size > 0 &&
        expressionUsesAnyIdentifier(init, bindings.propNames));

    if (!isDerived) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_DERIVED_STATE,
        node: init,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(init, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}
