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
import { getJsxStringAttr } from './jsx-attributes';
import { getJsxTagName } from './jsx-elements';
import {
  getClassMethodName,
  isReactComponentSuperclass,
} from './react-class-components';

const FACT_BIND_IN_JSX = 'ui.react.bind-in-jsx-prop';
const FACT_JSX_PROPS_SPREAD = 'ui.react.jsx-props-spread';
const FACT_CHILDREN_PROP = 'ui.react.children-prop';
const FACT_SET_STATE_DID_MOUNT = 'ui.react.set-state-in-component-did-mount';
const FACT_SET_STATE_DID_UPDATE = 'ui.react.set-state-in-component-did-update';
const FACT_DIRECT_STATE_MUTATION = 'ui.react.direct-state-mutation';
const FACT_TARGET_BLANK_WITHOUT_REL = 'ui.react.target-blank-without-rel';
const FACT_DUPLICATE_JSX_ATTRIBUTE = 'ui.react.duplicate-jsx-attribute';
const FACT_THIS_IN_FUNCTION_COMPONENT = 'ui.react.this-in-function-component';

function isBindCallExpression(
  expression: TSESTree.Expression,
): expression is TSESTree.CallExpression {
  return (
    expression.type === 'CallExpression' &&
    expression.callee.type === 'MemberExpression' &&
    !expression.callee.computed &&
    expression.callee.property.type === 'Identifier' &&
    expression.callee.property.name === 'bind'
  );
}

function isFunctionExpressionInJsxValue(expression: TSESTree.Expression): boolean {
  return expression.type === 'FunctionExpression';
}

function isSetStateCallee(callee: TSESTree.Expression | TSESTree.PrivateIdentifier): boolean {
  if (callee.type === 'MemberExpression' && !callee.computed) {
    return (
      callee.object.type === 'ThisExpression' &&
      callee.property.type === 'Identifier' &&
      callee.property.name === 'setState'
    );
  }

  return callee.type === 'Identifier' && callee.name === 'setState';
}

function expressionReferencesPrevPropsOrState(node: TSESTree.Node): boolean {
  let references = false;

  walkAst(node, (inner) => {
    if (
      !references &&
      inner.type === 'Identifier' &&
      (inner.name === 'prevProps' || inner.name === 'prevState')
    ) {
      references = true;
    }
  });

  return references;
}

function setStateCallHasUpdateGuard(
  callNode: TSESTree.CallExpression,
  ancestors: readonly TSESTree.Node[],
): boolean {
  for (const ancestor of ancestors) {
    if (ancestor === callNode) {
      continue;
    }

    if (ancestor.type === 'IfStatement' && expressionReferencesPrevPropsOrState(ancestor.test)) {
      return true;
    }
  }

  return false;
}

function isDirectStateAssignment(node: TSESTree.AssignmentExpression): boolean {
  const { left } = node;

  if (left.type !== 'MemberExpression' || left.computed) {
    return false;
  }

  if (left.object.type !== 'MemberExpression' || left.object.computed) {
    return false;
  }

  return (
    left.object.object.type === 'ThisExpression' &&
    left.object.property.type === 'Identifier' &&
    left.object.property.name === 'state'
  );
}

function relIncludesNoopener(rel: string | undefined): boolean {
  if (!rel || rel === '[expression]') {
    return false;
  }

  return rel
    .split(/\s+/u)
    .some((token) => token.toLowerCase() === 'noopener');
}

function isTargetBlank(opening: TSESTree.JSXOpeningElement): boolean {
  const target = getJsxStringAttr(opening, 'target');

  if (target === undefined) {
    return false;
  }

  if (target === '[expression]') {
    return true;
  }

  return target.toLowerCase() === '_blank';
}

function functionReturnsJsx(fn: TSESTree.Node): boolean {
  let returnsJsx = false;

  walkAst(fn, (node) => {
    if (returnsJsx) {
      return;
    }

    if (
      node.type === 'ReturnStatement' &&
      node.argument &&
      (node.argument.type === 'JSXElement' ||
        node.argument.type === 'JSXFragment')
    ) {
      returnsJsx = true;
    }
  });

  if (
    fn.type === 'ArrowFunctionExpression' &&
    (fn.body.type === 'JSXElement' || fn.body.type === 'JSXFragment')
  ) {
    return true;
  }

  return returnsJsx;
}

function isInsideClassBody(ancestors: readonly TSESTree.Node[]): boolean {
  return ancestors.some((ancestor) => ancestor.type === 'ClassBody');
}

function collectDuplicateJsxAttributeFacts(
  opening: TSESTree.JSXOpeningElement,
  context: TypeScriptFactDetectorContext,
  facts: ObservedFact[],
): void {
  const seen = new Map<string, TSESTree.JSXAttribute>();

  for (const attr of opening.attributes) {
    if (attr.type !== 'JSXAttribute' || attr.name.type !== 'JSXIdentifier') {
      continue;
    }

    const attrName = attr.name.name;
    const previous = seen.get(attrName);

    if (previous) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DUPLICATE_JSX_ATTRIBUTE,
          node: attr.name,
          nodeIds: context.nodeIds,
          props: {
            attribute: attrName,
          },
          text: attrName,
        }),
      );
      continue;
    }

    seen.set(attrName, attr);
  }
}

/** Detects React maintenance and security JSX/class patterns. */
export function collectReactMaintenancePatternFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type === 'JSXOpeningElement') {
      const tagName = getJsxTagName(node.name, context.sourceText);
      collectDuplicateJsxAttributeFacts(node, context, facts);

      if (tagName?.toLowerCase() === 'a' && isTargetBlank(node) && !relIncludesNoopener(getJsxStringAttr(node, 'rel'))) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_TARGET_BLANK_WITHOUT_REL,
            node,
            nodeIds: context.nodeIds,
            props: {
              tag: tagName,
            },
            text: getNodeText(node, context.sourceText),
          }),
        );
      }

      for (const attr of node.attributes) {
        if (attr.type === 'JSXSpreadAttribute') {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_JSX_PROPS_SPREAD,
              node: attr,
              nodeIds: context.nodeIds,
              props: {},
              text: getNodeText(attr, context.sourceText),
            }),
          );
          continue;
        }

        if (attr.type !== 'JSXAttribute' || attr.name.type !== 'JSXIdentifier') {
          continue;
        }

        if (attr.name.name === 'children') {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_CHILDREN_PROP,
              node: attr.name,
              nodeIds: context.nodeIds,
              props: {
                attribute: 'children',
              },
              text: 'children',
            }),
          );
        }

        const value = attr.value;

        if (value?.type !== 'JSXExpressionContainer' || value.expression.type === 'JSXEmptyExpression') {
          continue;
        }

        const expression = value.expression;

        if (isBindCallExpression(expression) || isFunctionExpressionInJsxValue(expression)) {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_BIND_IN_JSX,
              node: expression,
              nodeIds: context.nodeIds,
              props: {
                attribute: attr.name.name,
                pattern: isBindCallExpression(expression) ? 'bind' : 'inline-function',
              },
              text: getNodeText(expression, context.sourceText),
            }),
          );
        }
      }

      return;
    }

    if (node.type === 'AssignmentExpression' && isDirectStateAssignment(node)) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DIRECT_STATE_MUTATION,
          node,
          nodeIds: context.nodeIds,
          props: {},
          text: getNodeText(node, context.sourceText),
        }),
      );
      return;
    }

    if (node.type === 'CallExpression' && isSetStateCallee(node.callee)) {
      const lifecycleMethod = ancestors.find(
        (ancestor): ancestor is TSESTree.MethodDefinition =>
          ancestor.type === 'MethodDefinition',
      );
      const classNode = ancestors.find(
        (ancestor): ancestor is TSESTree.ClassDeclaration | TSESTree.ClassExpression =>
          ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
      );

      if (!lifecycleMethod || !classNode || !isReactComponentSuperclass(classNode.superClass, context.sourceText)) {
        return;
      }

      const methodName = getClassMethodName(lifecycleMethod);

      if (methodName === 'componentDidMount') {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_SET_STATE_DID_MOUNT,
            node: node.callee,
            nodeIds: context.nodeIds,
            props: {
              method: methodName,
            },
            text: getNodeText(node.callee, context.sourceText),
          }),
        );
        return;
      }

      if (
        methodName === 'componentDidUpdate' &&
        !setStateCallHasUpdateGuard(node, ancestors)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_SET_STATE_DID_UPDATE,
            node: node.callee,
            nodeIds: context.nodeIds,
            props: {
              method: methodName,
            },
            text: getNodeText(node.callee, context.sourceText),
          }),
        );
      }

      return;
    }

    if (
      node.type === 'MemberExpression' &&
      !node.computed &&
      node.object.type === 'ThisExpression' &&
      ancestors.some(
        (ancestor) =>
          ancestor.type === 'FunctionDeclaration' ||
          ancestor.type === 'FunctionExpression' ||
          ancestor.type === 'ArrowFunctionExpression',
      )
    ) {
      const enclosingFunction = [...ancestors]
        .reverse()
        .find(
          (ancestor): ancestor is
            | TSESTree.FunctionDeclaration
            | TSESTree.FunctionExpression
            | TSESTree.ArrowFunctionExpression =>
            ancestor.type === 'FunctionDeclaration' ||
            ancestor.type === 'FunctionExpression' ||
            ancestor.type === 'ArrowFunctionExpression',
        );

      if (
        !enclosingFunction ||
        isInsideClassBody(ancestors) ||
        !functionReturnsJsx(enclosingFunction)
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_THIS_IN_FUNCTION_COMPONENT,
          node: node.object,
          nodeIds: context.nodeIds,
          props: {},
          text: getNodeText(node, context.sourceText),
        }),
      );
    }
  });

  return dedupeFactsByRange(facts);
}
