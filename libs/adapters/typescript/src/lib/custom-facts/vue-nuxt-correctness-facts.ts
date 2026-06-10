import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst } from '../ast';
import {
  createObservedFact,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const collectVueNuxtCorrectnessFacts: TypeScriptFactDetector = (
  context: TypeScriptFactDetectorContext,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    // Detect JSX: <NuxtLink href="...">
    if (node.type === 'JSXOpeningElement') {
      const elementName = node.name;
      let tagName: string | undefined;

      if (elementName.type === 'JSXIdentifier') {
        tagName = elementName.name;
      }

      if (tagName !== 'NuxtLink') {
        return;
      }

      for (const attr of node.attributes) {
        if (attr.type !== 'JSXAttribute') {
          continue;
        }

        if (attr.name.type !== 'JSXIdentifier') {
          continue;
        }

        if (attr.name.name === 'href') {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: 'nuxt-correctness.nuxt-link-href',
              node: attr,
              nodeIds,
              text: getNodeText(attr, sourceText),
              props: {
                tagName: 'NuxtLink',
                attribute: 'href',
              },
            }),
          );
        }
      }
    }
  });

  return facts;
};
