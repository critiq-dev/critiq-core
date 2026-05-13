import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import {
  collectModuleNamespaceLocalNames,
  collectNamedImportLocalNames,
  collectRequiredNamedLocalNames,
} from './react-class-components';

const FACT_DEPRECATED_REACT_DOM_API = 'ui.react.deprecated-react-dom-root-api';
const FACT_DEPRECATED_CREATE_FACTORY = 'ui.react.deprecated-create-factory';

const DEPRECATED_REACT_DOM_METHODS = new Set([
  'render',
  'hydrate',
  'unmountComponentAtNode',
]);

function collectReactDomCalleeBindings(program: TSESTree.Program): {
  namespaceObjects: Set<string>;
  directMethodNames: Set<string>;
} {
  const namespaceObjects = new Set([
    'ReactDOM',
    ...collectModuleNamespaceLocalNames(program, 'react-dom'),
  ]);
  const directMethodNames = new Set([
    ...collectNamedImportLocalNames(program, 'react-dom', 'render'),
    ...collectNamedImportLocalNames(program, 'react-dom', 'hydrate'),
    ...collectNamedImportLocalNames(
      program,
      'react-dom',
      'unmountComponentAtNode',
    ),
    ...collectRequiredNamedLocalNames(program, 'react-dom', 'render'),
    ...collectRequiredNamedLocalNames(program, 'react-dom', 'hydrate'),
    ...collectRequiredNamedLocalNames(
      program,
      'react-dom',
      'unmountComponentAtNode',
    ),
  ]);

  return { namespaceObjects, directMethodNames };
}

function collectCreateFactoryBindings(program: TSESTree.Program): {
  reactNamespaceObjects: Set<string>;
  directNames: Set<string>;
} {
  const reactNamespaceObjects = new Set([
    'React',
    ...collectModuleNamespaceLocalNames(program, 'react'),
  ]);
  const directNames = new Set([
    ...collectNamedImportLocalNames(program, 'react', 'createFactory'),
    ...collectRequiredNamedLocalNames(program, 'react', 'createFactory'),
  ]);

  return { reactNamespaceObjects, directNames };
}

/** Flags legacy React 17-era entrypoints superseded by `createRoot` and function components. */
export function collectDeprecatedReactApiFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const reactDomBindings = collectReactDomCalleeBindings(context.program);
  const createFactoryBindings = collectCreateFactoryBindings(context.program);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type === 'Identifier' &&
      reactDomBindings.directMethodNames.has(node.callee.name)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_REACT_DOM_API,
          node: node.callee,
          nodeIds: context.nodeIds,
          props: {
            symbol: node.callee.name,
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );

      return;
    }

    if (
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'Identifier' &&
      node.callee.property.type === 'Identifier' &&
      DEPRECATED_REACT_DOM_METHODS.has(node.callee.property.name) &&
      reactDomBindings.namespaceObjects.has(node.callee.object.name)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_REACT_DOM_API,
          node: node.callee.property,
          nodeIds: context.nodeIds,
          props: {
            symbol: `${node.callee.object.name}.${node.callee.property.name}`,
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );

      return;
    }

    if (
      node.callee.type === 'Identifier' &&
      createFactoryBindings.directNames.has(node.callee.name)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_CREATE_FACTORY,
          node: node.callee,
          nodeIds: context.nodeIds,
          props: {
            symbol: node.callee.name,
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );

      return;
    }

    if (
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'Identifier' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'createFactory' &&
      createFactoryBindings.reactNamespaceObjects.has(node.callee.object.name)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_CREATE_FACTORY,
          node: node.callee.property,
          nodeIds: context.nodeIds,
          props: {
            symbol: `${node.callee.object.name}.createFactory`,
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );
    }
  });

  return dedupeFactsByRange(facts);
}
