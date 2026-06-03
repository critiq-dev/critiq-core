import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { FACT_KINDS } from './constants';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';

const openExternalCalleePattern = /(^|\.)(openExternal)$/u;
const requestDrivenUrlPattern = /\b(?:req|request|body|query|params)\b/u;

export function collectElectronShellOpenExternalUnvalidatedFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !openExternalCalleePattern.test(calleeText)) {
      return;
    }

    const urlText = getNodeText(
      node.arguments[0] as TSESTree.Expression | undefined,
      context.sourceText,
    );

    if (!urlText || !requestDrivenUrlPattern.test(urlText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.electronShellOpenExternalUnvalidated,
        node,
        nodeIds: context.nodeIds,
        text: calleeText,
        props: {
          url: urlText,
        },
      }),
    );
  });

  return facts;
}
