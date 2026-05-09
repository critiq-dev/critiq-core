import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  walkAstWithAncestors,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { isExplicitDevOnlyContext } from './disclosure';

/**
 * Collects facts for leftover `console.trace()` calls in production paths.
 *
 * `console.trace` dumps a stack trace to stdout/stderr and is almost always
 * developer leftover. Bare `debugger;` statements are intentionally excluded
 * from this fact because the existing `ts.runtime.no-debugger-statement` rule
 * already covers them in TypeScript files.
 *
 * Calls wrapped in an explicit dev-only branch
 * (`process.env.NODE_ENV !== 'production'`, `import.meta.env.DEV`, or
 * `__DEV__`) are not flagged so local-only diagnostics keep working.
 */
export function collectDebugStatementInSourceFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'console.trace') {
      return;
    }

    if (isExplicitDevOnlyContext(node, ancestors, context.sourceText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.debugStatementInSource,
        node,
        nodeIds: context.nodeIds,
        props: {
          statement: 'console.trace',
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}
