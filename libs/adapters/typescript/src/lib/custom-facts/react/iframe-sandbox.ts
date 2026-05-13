import type { ObservedFact } from '@critiq/core-rules-engine';

import { FACT_KINDS } from '../additional-public-security/constants';
import {
  createObservedFact,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { hasJsxAttribute } from './jsx-attributes';
import { getJsxTagName } from './jsx-elements';

/** Intrinsic `<iframe>` elements without a `sandbox` attribute. */
export function collectIframeMissingSandboxFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXOpeningElement') {
      return;
    }

    const tagName = getJsxTagName(node.name, context.sourceText);

    if (tagName?.toLowerCase() !== 'iframe') {
      return;
    }

    if (hasJsxAttribute(node, 'sandbox')) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.iframeMissingSandboxAttribute,
        node,
        nodeIds: context.nodeIds,
        text: '<iframe>',
      }),
    );
  });

  return facts;
}
