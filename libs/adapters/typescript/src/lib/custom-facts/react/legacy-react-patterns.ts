import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  walkAstWithAncestors,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { dedupeFactsByRange } from './dedupe-facts';
import {
  collectModuleNamespaceLocalNames,
  collectNamedImportLocalNames,
  collectRequiredNamedLocalNames,
  isReactComponentSuperclass,
  LEGACY_LIFECYCLE_METHODS,
} from './react-class-components';

const FACT_FIND_DOM_NODE = 'ui.react.find-dom-node';
const FACT_LEGACY_LIFECYCLE = 'ui.react.legacy-lifecycle';
const FACT_STRING_REF = 'ui.react.string-ref';

function isLifecycleOwner(
  ancestors: readonly TSESTree.Node[],
  sourceText: string,
): boolean {
  const classNode = [...ancestors]
    .reverse()
    .find(
      (ancestor) =>
        ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
    );

  if (!classNode) {
    return false;
  }

  return isReactComponentSuperclass(classNode.superClass, sourceText);
}

function collectFindDomNodeBindings(
  program: TSESTree.Program,
): { directNames: Set<string>; namespaceNames: Set<string> } {
  const directNames = new Set([
    ...collectNamedImportLocalNames(program, 'react-dom', 'findDOMNode'),
    ...collectRequiredNamedLocalNames(program, 'react-dom', 'findDOMNode'),
  ]);
  const namespaceNames = new Set([
    'ReactDOM',
    ...collectModuleNamespaceLocalNames(program, 'react-dom'),
  ]);

  return { directNames, namespaceNames };
}

/** Detects legacy React class lifecycles, string refs, and findDOMNode usage. */
export function collectLegacyReactPatternFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const findDomNodeBindings = collectFindDomNodeBindings(context.program);

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type === 'MethodDefinition' || node.type === 'PropertyDefinition') {
      const methodName = getLifecycleMemberName(node);

      if (
        methodName &&
        LEGACY_LIFECYCLE_METHODS.has(methodName) &&
        isLifecycleOwner(ancestors, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_LEGACY_LIFECYCLE,
            node: node.key as TSESTree.Node,
            nodeIds: context.nodeIds,
            props: {
              method: methodName,
              methodName,
            },
            text: methodName,
          }),
        );
      }

      return;
    }

    if (node.type === 'CallExpression') {
      if (
        node.callee.type === 'Identifier' &&
        findDomNodeBindings.directNames.has(node.callee.name)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_FIND_DOM_NODE,
            node: node.callee,
            nodeIds: context.nodeIds,
            props: {
              callee: node.callee.name,
            },
            text: getNodeText(node.callee, context.sourceText),
          }),
        );
      }

      if (
        node.callee.type === 'MemberExpression' &&
        !node.callee.computed &&
        node.callee.object.type === 'Identifier' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'findDOMNode' &&
        findDomNodeBindings.namespaceNames.has(node.callee.object.name)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_FIND_DOM_NODE,
            node: node.callee.property,
            nodeIds: context.nodeIds,
            props: {
              callee: `${node.callee.object.name}.findDOMNode`,
            },
            text: getNodeText(node.callee, context.sourceText),
          }),
        );
      }

      return;
    }

    if (
      node.type === 'JSXAttribute' &&
      node.name.type === 'JSXIdentifier' &&
      node.name.name === 'ref'
    ) {
      if (
        node.value?.type === 'Literal' &&
        typeof node.value.value === 'string' &&
        node.value.value.trim().length > 0
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_STRING_REF,
            node: node.value,
            nodeIds: context.nodeIds,
            props: {
              refName: node.value.value,
            },
            text: node.value.value,
          }),
        );
      }

      if (
        node.value?.type === 'JSXExpressionContainer' &&
        node.value.expression.type === 'Literal' &&
        typeof node.value.expression.value === 'string' &&
        node.value.expression.value.trim().length > 0
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_STRING_REF,
            node: node.value.expression,
            nodeIds: context.nodeIds,
            props: {
              refName: node.value.expression.value,
            },
            text: node.value.expression.value,
          }),
        );
      }
    }
  });

  return dedupeFactsByRange(facts);
}

function getLifecycleMemberName(
  node: TSESTree.MethodDefinition | TSESTree.PropertyDefinition,
): string | undefined {
  if (
    node.type === 'PropertyDefinition' &&
    (!node.value ||
      (node.value.type !== 'ArrowFunctionExpression' &&
        node.value.type !== 'FunctionExpression'))
  ) {
    return undefined;
  }

  if (node.key.type === 'Identifier') {
    return node.key.name;
  }

  if (node.key.type === 'Literal' && typeof node.key.value === 'string') {
    return node.key.value;
  }

  return undefined;
}
