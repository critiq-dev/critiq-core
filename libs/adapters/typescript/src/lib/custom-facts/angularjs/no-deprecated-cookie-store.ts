import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { hasAngularJsContext } from './angularjs-context';

function isAngularJsIdentifier(name: string): boolean {
  return name === '$cookieStore';
}

export function collectNoDeprecatedCookieStoreFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!hasAngularJsContext(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const seen = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type !== 'Identifier') {
      return;
    }

    if (!isAngularJsIdentifier(node.name)) {
      return;
    }

    const id = `${node.loc.start.line}:${node.loc.start.column}`;

    if (seen.has(id)) {
      return;
    }

    seen.add(id);

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.NO_DEPRECATED_COOKIE_STORE,
        node,
        nodeIds: context.nodeIds,
        props: {
          symbol: node.name,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}
