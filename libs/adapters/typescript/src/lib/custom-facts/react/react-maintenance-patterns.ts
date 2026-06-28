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
import { flatJsxElementsInFragment, getJsxTagName } from './jsx-elements';
import {
  collectModuleNamespaceLocalNames,
  collectNamedImportLocalNames,
  collectRequiredNamedLocalNames,
  getClassMethodName,
  isReactComponentSuperclass,
  LEGACY_LIFECYCLE_METHODS,
} from './react-class-components';
import { getLifecycleMemberName } from './legacy-react-patterns';
import { isJsxSpreadExempt } from './is-jsx-spread-exempt';

const FACT_BIND_IN_JSX = 'ui.react.bind-in-jsx-prop';
const FACT_JSX_PROPS_SPREAD = 'ui.react.jsx-props-spread';
const FACT_CHILDREN_PROP = 'ui.react.children-prop';
const FACT_SET_STATE_DID_MOUNT = 'ui.react.set-state-in-component-did-mount';
const FACT_SET_STATE_DID_UPDATE = 'ui.react.set-state-in-component-did-update';
const FACT_SET_STATE_WILL_UPDATE = 'ui.react.set-state-in-component-will-update';
const FACT_DIRECT_STATE_MUTATION = 'ui.react.direct-state-mutation';
const FACT_DEPRECATED_IS_MOUNTED = 'ui.react.deprecated-is-mounted';
const FACT_SHOULD_COMPONENT_UPDATE = 'ui.react.should-component-update';
const FACT_LIFECYCLE_METHOD_TYPO = 'ui.react.lifecycle-method-typo';
const FACT_INVALID_MARKUP_CHARACTERS = 'ui.react.invalid-markup-characters';
const FACT_RENDER_RETURN_VALUE = 'ui.react.render-return-value';
const FACT_TARGET_BLANK_WITHOUT_REL = 'ui.react.target-blank-without-rel';
const FACT_DUPLICATE_JSX_ATTRIBUTE = 'ui.react.duplicate-jsx-attribute';
const FACT_THIS_IN_FUNCTION_COMPONENT = 'ui.react.this-in-function-component';
const FACT_UNNECESSARY_FRAGMENT = 'ui.react.unnecessary-fragment';
const FACT_THIS_STATE_IN_SET_STATE = 'ui.react.this-state-in-set-state';

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

/** Detects both `this.state = value` and `this.state.X = value` assignments. */
function isDirectStateAssignment(node: TSESTree.AssignmentExpression): boolean {
  const { left } = node;

  if (left.type !== 'MemberExpression' || left.computed) {
    return false;
  }

  // `this.state = value`
  if (
    left.object.type === 'ThisExpression' &&
    left.property.type === 'Identifier' &&
    left.property.name === 'state'
  ) {
    return true;
  }

  // `this.state.X = value`
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

const LIFECYCLE_METHODS = new Set([
  'constructor',
  'render',
  'componentDidMount',
  'componentDidUpdate',
  'componentWillUnmount',
  'shouldComponentUpdate',
  'getDerivedStateFromProps',
  'getSnapshotBeforeUpdate',
  'componentDidCatch',
  'getDerivedStateFromError',
  ...LEGACY_LIFECYCLE_METHODS,
]);

function levenshteinDistance(a: string, b: string): number {
  const an = a.length;
  const bn = b.length;
  const matrix: number[] = new Array<number>((bn + 1) * (an + 1));

  for (let i = 0; i <= an; i++) {
    matrix[i] = i;
  }

  for (let j = 0; j <= bn; j++) {
    matrix[j * (an + 1)] = j;
  }

  for (let j = 1; j <= bn; j++) {
    for (let i = 1; i <= an; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j * (an + 1) + i] = Math.min(
        matrix[j * (an + 1) + i - 1] + 1,
        matrix[(j - 1) * (an + 1) + i] + 1,
        matrix[(j - 1) * (an + 1) + i - 1] + cost,
      );
    }
  }

  return matrix[bn * (an + 1) + an];
}

function findClosestLifecycleMatch(name: string): string | undefined {
  const lower = name.toLowerCase();
  let bestDistance = Infinity;
  let bestMatch: string | undefined;

  for (const lifecycle of LIFECYCLE_METHODS) {
    const dist = levenshteinDistance(lower, lifecycle.toLowerCase());
    if (dist < bestDistance) {
      bestDistance = dist;
      bestMatch = lifecycle;
    }
  }

  if (bestMatch && bestDistance > 0 && bestDistance <= 2) {
    return bestMatch;
  }

  return undefined;
}

function isLikelyLifecycleTypo(name: string): boolean {
  const lower = name.toLowerCase();

  if (lower.length < 5) {
    return false;
  }

  if (
    !lower.startsWith('comp') &&
    !lower.startsWith('render') &&
    !lower.startsWith('should')
  ) {
    return false;
  }

  if (LIFECYCLE_METHODS.has(name)) {
    return false;
  }

  return findClosestLifecycleMatch(name) !== undefined;
}

function collectIsMountedBindings(
  program: TSESTree.Program,
): { directNames: Set<string>; namespaceNames: Set<string> } {
  const directNames = new Set([
    ...collectNamedImportLocalNames(program, 'react-dom', 'isMounted'),
    ...collectRequiredNamedLocalNames(program, 'react-dom', 'isMounted'),
  ]);
  const namespaceNames = new Set([
    'ReactDOM',
    ...collectModuleNamespaceLocalNames(program, 'react-dom'),
  ]);

  return { directNames, namespaceNames };
}

function hasInvalidMarkupCharacters(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);

    if (code === 0x0009 || code === 0x000a || code === 0x000d) {
      continue;
    }

    if (code <= 0x001f) {
      return true;
    }

    if (code === 0x200b || code === 0x200c || code === 0x200d || code === 0xfeff) {
      return true;
    }
  }

  return false;
}

const VALID_RENDER_RETURN_TYPES = new Set([
  'JSXElement',
  'JSXFragment',
  'NullLiteral',
  'StringLiteral',
  'BooleanLiteral',
]);

function isBooleanLiteralNode(node: TSESTree.Expression): boolean {
  return node.type === 'Literal' && typeof node.value === 'boolean';
}

function isStringLiteralNode(node: TSESTree.Expression): boolean {
  return node.type === 'Literal' && typeof node.value === 'string';
}

function isNullLiteralNode(node: TSESTree.Expression): boolean {
  return node.type === 'Literal' && node.value === null;
}

function renderReturnIsInvalid(returnArg: TSESTree.Expression): boolean {
  if (
    returnArg.type === 'JSXElement' ||
    returnArg.type === 'JSXFragment'
  ) {
    return false;
  }

  if (isNullLiteralNode(returnArg)) {
    return false;
  }

  if (isStringLiteralNode(returnArg)) {
    return false;
  }

  if (isBooleanLiteralNode(returnArg)) {
    return false;
  }

  if (returnArg.type === 'TemplateLiteral') {
    return false;
  }

  if (returnArg.type === 'ConditionalExpression') {
    return (
      renderReturnIsInvalid(returnArg.consequent) ||
      renderReturnIsInvalid(returnArg.alternate)
    );
  }

  if (returnArg.type === 'LogicalExpression') {
    if (returnArg.operator === '&&') {
      return renderReturnIsInvalid(returnArg.right);
    }

    return (
      renderReturnIsInvalid(returnArg.left) ||
      renderReturnIsInvalid(returnArg.right)
    );
  }

  return true;
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
  const isMountedBindings = collectIsMountedBindings(context.program);

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type === 'JSXFragment') {
      const elements = flatJsxElementsInFragment(node);
      if (elements.length === 1) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_UNNECESSARY_FRAGMENT,
            node,
            nodeIds: context.nodeIds,
            props: {},
            text: getNodeText(node, context.sourceText),
          }),
        );
      }
    }

    if (node.type === 'JSXOpeningElement') {
      const tagName = getJsxTagName(node.name, context.sourceText);

      if (tagName === 'Fragment' || tagName === 'React.Fragment') {
        const parentElement = ancestors[ancestors.length - 1];
        if (parentElement.type === 'JSXElement') {
          const hasKey = node.attributes.some(
            (attr) =>
              attr.type === 'JSXAttribute' &&
              attr.name.type === 'JSXIdentifier' &&
              attr.name.name === 'key',
          );
          if (!hasKey) {
            const elements = parentElement.children.filter(
              (child): child is TSESTree.JSXElement => child.type === 'JSXElement',
            );
            if (elements.length === 1) {
              facts.push(
                createObservedFact({
                  appliesTo: 'function',
                  kind: FACT_UNNECESSARY_FRAGMENT,
                  node: parentElement,
                  nodeIds: context.nodeIds,
                  props: {},
                  text: getNodeText(parentElement, context.sourceText),
                }),
              );
            }
          }
        }
      }

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
          if (isJsxSpreadExempt(attr)) {
            continue;
          }

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
      const classNode = ancestors.find(
        (ancestor): ancestor is TSESTree.ClassDeclaration | TSESTree.ClassExpression =>
          ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
      );

      if (!classNode || !isReactComponentSuperclass(classNode.superClass, context.sourceText)) {
        return;
      }

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
      const classNode = ancestors.find(
        (ancestor): ancestor is TSESTree.ClassDeclaration | TSESTree.ClassExpression =>
          ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
      );

      if (!classNode || !isReactComponentSuperclass(classNode.superClass, context.sourceText)) {
        return;
      }

      const lifecycleMethod = ancestors.find(
        (ancestor): ancestor is TSESTree.MethodDefinition =>
          ancestor.type === 'MethodDefinition',
      );

      if (lifecycleMethod) {
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

        if (methodName === 'componentWillUpdate') {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_SET_STATE_WILL_UPDATE,
              node: node.callee,
              nodeIds: context.nodeIds,
              props: {
                method: methodName,
              },
              text: getNodeText(node.callee, context.sourceText),
            }),
          );
        }
      }

      const firstArg = node.arguments[0];
      if (firstArg && firstArg.type !== 'SpreadElement') {
        let hasThisState = false;
        walkAst(firstArg, (inner) => {
          if (
            !hasThisState &&
            inner.type === 'MemberExpression' &&
            !inner.computed &&
            inner.object.type === 'ThisExpression' &&
            inner.property.type === 'Identifier' &&
            inner.property.name === 'state'
          ) {
            hasThisState = true;
          }
        });

        if (hasThisState) {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_THIS_STATE_IN_SET_STATE,
              node: node.callee,
              nodeIds: context.nodeIds,
              props: {},
              text: getNodeText(node.callee, context.sourceText),
            }),
          );
        }
      }

      return;
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'ThisExpression' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'isMounted'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_IS_MOUNTED,
          node: node.callee.property,
          nodeIds: context.nodeIds,
          props: {
            callee: 'this.isMounted',
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );
      return;
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'Identifier' &&
      node.callee.property.type === 'Identifier' &&
      node.callee.property.name === 'isMounted'
    ) {
      if (isMountedBindings.namespaceNames.has(node.callee.object.name)) {
        facts.push(
          createObservedFact({
            appliesTo: 'function',
            kind: FACT_DEPRECATED_IS_MOUNTED,
            node: node.callee.property,
            nodeIds: context.nodeIds,
            props: {
              callee: `${node.callee.object.name}.isMounted`,
            },
            text: getNodeText(node.callee, context.sourceText),
          }),
        );
        return;
      }
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'Identifier' &&
      (isMountedBindings.directNames.has(node.callee.name))
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_DEPRECATED_IS_MOUNTED,
          node: node.callee,
          nodeIds: context.nodeIds,
          props: {
            callee: node.callee.name,
          },
          text: getNodeText(node.callee, context.sourceText),
        }),
      );
      return;
    }

    if (node.type === 'MethodDefinition' || node.type === 'PropertyDefinition') {
      const methodName = getLifecycleMemberName(node);

      if (methodName === 'shouldComponentUpdate') {
        const classNode = [...ancestors]
          .reverse()
          .find(
            (ancestor) =>
              ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
          );

        if (classNode && isReactComponentSuperclass(classNode.superClass, context.sourceText)) {
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_SHOULD_COMPONENT_UPDATE,
              node: node.key as TSESTree.Node,
              nodeIds: context.nodeIds,
              props: {
                method: methodName,
              },
              text: methodName,
            }),
          );
        }
        return;
      }

      if (methodName && isLikelyLifecycleTypo(methodName)) {
        const classNode = [...ancestors]
          .reverse()
          .find(
            (ancestor) =>
              ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
          );

        if (classNode && isReactComponentSuperclass(classNode.superClass, context.sourceText)) {
          const closestMatch = findClosestLifecycleMatch(methodName);
          facts.push(
            createObservedFact({
              appliesTo: 'function',
              kind: FACT_LIFECYCLE_METHOD_TYPO,
              node: node.key as TSESTree.Node,
              nodeIds: context.nodeIds,
              props: {
                method: methodName,
                suggestion: closestMatch ?? '',
              },
              text: methodName,
            }),
          );
        }
        return;
      }
    }

    if (
      node.type === 'JSXText' &&
      hasInvalidMarkupCharacters(node.value)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'function',
          kind: FACT_INVALID_MARKUP_CHARACTERS,
          node,
          nodeIds: context.nodeIds,
          props: {},
          text: node.value,
        }),
      );
      return;
    }

    if (
      node.type === 'ReturnStatement' &&
      node.argument
    ) {
      const methodNode = ancestors.find(
        (ancestor): ancestor is TSESTree.MethodDefinition =>
          ancestor.type === 'MethodDefinition',
      );

      if (methodNode) {
        const returnMethodName = getClassMethodName(methodNode);

        if (returnMethodName === 'render') {
          const classNode = ancestors.find(
            (ancestor): ancestor is TSESTree.ClassDeclaration | TSESTree.ClassExpression =>
              ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression',
          );

          if (
            classNode &&
            isReactComponentSuperclass(classNode.superClass, context.sourceText) &&
            renderReturnIsInvalid(node.argument)
          ) {
            facts.push(
              createObservedFact({
                appliesTo: 'function',
                kind: FACT_RENDER_RETURN_VALUE,
                node: node.argument,
                nodeIds: context.nodeIds,
                props: {},
                text: getNodeText(node.argument, context.sourceText),
              }),
            );
          }
        }
      }
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
