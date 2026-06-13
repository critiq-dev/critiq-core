import type { ObservedFact } from '@critiq/core-rules-engine';

import { FACT_KINDS } from '../additional-public-security/constants';
import {
  createObservedFact,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { hasJsxAttribute } from './jsx-attributes';
import { getJsxTagName } from './jsx-elements';

/**
 * Intrinsic `<iframe>` elements without a `sandbox` attribute.
 *
 * Skips iframes with `allowFullScreen` or `allow` attributes — these signal
 * intentional trust (e.g., app marketplace embeds, payment gateways) or
 * explicit CORS/permission management.
 */
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

    // allowFullScreen signals intentional trust — app marketplace embeds,
    // payment gateways that need full browser capabilities.
    if (hasJsxAttribute(node, 'allowFullScreen')) {
      return;
    }

    // allow attribute signals explicit CORS/permission policy management.
    if (hasJsxAttribute(node, 'allow')) {
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
