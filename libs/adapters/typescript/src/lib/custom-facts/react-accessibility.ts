import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from './shared';

const FACT_INDEX_KEY = 'ui.react.index-key-in-list';
const FACT_DERIVED_STATE = 'ui.react.derived-state-from-props';
const FACT_A11Y_NAME = 'ui.react.missing-accessible-name';
const FACT_UNCONTROLLED = 'ui.react.uncontrolled-controlled-input';

export function detectReactAccessibilityFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  facts.push(...collectIndexKeyFacts(context));
  facts.push(...collectDerivedStateFacts(context));
  facts.push(...collectMissingAccessibleNameFacts(context));
  facts.push(...collectUncontrolledControlledInputFacts(context));

  return facts;
}

function unwrapChainExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier,
): TSESTree.Expression | TSESTree.PrivateIdentifier {
  if (node.type === 'ChainExpression') {
    return unwrapChainExpression(node.expression);
  }

  return node;
}

function isMapCall(call: TSESTree.CallExpression): boolean {
  const callee = unwrapChainExpression(
    call.callee as TSESTree.Expression,
  );

  if (callee.type !== 'MemberExpression') {
    return false;
  }

  if (callee.computed) {
    return false;
  }

  const prop = callee.property;

  return prop.type === 'Identifier' && prop.name === 'map';
}

function collectCallbackParams(
  callback: TSESTree.CallExpressionArgument | undefined,
): { indexName: string | undefined } {
  if (!callback || callback.type === 'SpreadElement') {
    return { indexName: undefined };
  }

  if (
    callback.type === 'ArrowFunctionExpression' ||
    callback.type === 'FunctionExpression'
  ) {
    const indexParam = callback.params[1];

    if (
      indexParam &&
      indexParam.type === 'Identifier' &&
      indexParam.name !== undefined
    ) {
      return { indexName: indexParam.name };
    }
  }

  return { indexName: undefined };
}

function expressionUsesIdentifier(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier | undefined | null,
  name: string,
): boolean {
  if (!expr || expr.type === 'PrivateIdentifier') {
    return false;
  }

  let found = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (found) {
      return;
    }

    if (node.type === 'Identifier' && node.name === name) {
      found = true;
    }
  });

  return found;
}

function jsxKeyUsesIndex(
  attr: TSESTree.JSXAttribute | TSESTree.JSXSpreadAttribute,
  indexName: string,
): boolean {
  if (attr.type !== 'JSXAttribute') {
    return false;
  }

  const attrName = attr.name;

  if (attrName.type !== 'JSXIdentifier' || attrName.name !== 'key') {
    return false;
  }

  const value = attr.value;

  if (!value || value.type !== 'JSXExpressionContainer') {
    return false;
  }

  const expr = value.expression;

  if (expr.type === 'JSXEmptyExpression') {
    return false;
  }

  if (expr.type === 'Identifier') {
    return expr.name === indexName;
  }

  return expressionUsesIdentifier(expr as TSESTree.Expression, indexName);
}

function unwrapExpression(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
): TSESTree.Expression | TSESTree.PrivateIdentifier {
  if (expr.type === 'TSAsExpression' || expr.type === 'TSTypeAssertion') {
    return unwrapExpression(expr.expression);
  }

  if ((expr as { type?: string }).type === 'ParenthesizedExpression') {
    return unwrapExpression(
      (expr as { expression: TSESTree.Expression }).expression,
    );
  }

  return expr;
}

function flagJsxRootsInExpression(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
  flagIssue: (jsx: TSESTree.JSXElement | TSESTree.JSXFragment) => void,
): void {
  const root = unwrapExpression(expr);

  if (root.type === 'JSXElement' || root.type === 'JSXFragment') {
    flagIssue(root);

    return;
  }

  walkAst(root as TSESTree.Node, (child) => {
    if (child.type === 'JSXElement' || child.type === 'JSXFragment') {
      flagIssue(child);
    }
  });
}

function callExpressionFromWalkNode(
  node: TSESTree.Node,
): TSESTree.CallExpression | undefined {
  if (node.type === 'CallExpression') {
    return node;
  }

  if (node.type === 'ChainExpression' && node.expression.type === 'CallExpression') {
    return node.expression;
  }

  return undefined;
}

function collectIndexKeyFacts(context: TypeScriptFactDetectorContext): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    const call = callExpressionFromWalkNode(node);

    if (!call || !isMapCall(call)) {
      return;
    }

    const callback = call.arguments[0];
    const { indexName } = collectCallbackParams(callback);

    if (!indexName) {
      return;
    }

    const flagIssue = (jsxOrFrag: TSESTree.JSXElement | TSESTree.JSXFragment) => {
      const elements =
        jsxOrFrag.type === 'JSXElement'
          ? [jsxOrFrag]
          : flatJsxElementsInFragment(jsxOrFrag);

      for (const jsx of elements) {
        const attrs = jsx.openingElement.attributes;

        for (const attr of attrs) {
          if (jsxKeyUsesIndex(attr, indexName)) {
            const issueNode =
              attr.type === 'JSXAttribute' && attr.value?.type === 'JSXExpressionContainer'
                ? attr.value.expression
                : jsx.openingElement;

            facts.push(
              createObservedFact({
                appliesTo: 'function',
                kind: FACT_INDEX_KEY,
                node: issueNode as TSESTree.Node,
                nodeIds: context.nodeIds,
                props: {
                  indexParameter: indexName,
                },
                text: getNodeText(issueNode as TSESTree.Node, context.sourceText),
              }),
            );

            return;
          }
        }
      }
    };

    if (
      callback &&
      (callback.type === 'ArrowFunctionExpression' ||
        callback.type === 'FunctionExpression')
    ) {
      const body = callback.body;

      if (body.type === 'BlockStatement') {
        for (const stmt of body.body) {
          if (stmt.type === 'ReturnStatement' && stmt.argument) {
            flagJsxRootsInExpression(stmt.argument, flagIssue);
          }
        }
      } else {
        flagJsxRootsInExpression(body, flagIssue);
      }
    }
  });

  return dedupeFactsByRange(facts);
}

function flatJsxElementsInFragment(
  frag: TSESTree.JSXFragment,
): TSESTree.JSXElement[] {
  const out: TSESTree.JSXElement[] = [];

  for (const child of frag.children) {
    if (child.type === 'JSXElement') {
      out.push(child);
    }
  }

  return out;
}

function dedupeFactsByRange(facts: ObservedFact[]): ObservedFact[] {
  const seen = new Set<string>();

  return facts.filter((fact) => {
    const key = `${fact.range.startLine}:${fact.range.startColumn}:${fact.kind}`;

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);

    return true;
  });
}

function collectPatternBindingNames(pattern: TSESTree.Node): string[] {
  if (pattern.type === 'Identifier') {
    return [pattern.name];
  }

  if (pattern.type === 'ObjectPattern') {
    const names: string[] = [];

    for (const prop of pattern.properties) {
      if (prop.type === 'Property') {
        names.push(...collectPatternBindingNames(prop.value as TSESTree.Node));
      } else if (prop.type === 'RestElement') {
        names.push(...collectPatternBindingNames(prop.argument));
      }
    }

    return names;
  }

  if (pattern.type === 'ArrayPattern') {
    const names: string[] = [];

    for (const el of pattern.elements) {
      if (!el) {
        continue;
      }

      names.push(...collectPatternBindingNames(el));
    }

    return names;
  }

  if (pattern.type === 'AssignmentPattern') {
    return collectPatternBindingNames(pattern.left);
  }

  if (pattern.type === 'RestElement') {
    return collectPatternBindingNames(pattern.argument);
  }

  return [];
}

function getFirstParamPropBindings(
  fn:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
): { propNames: Set<string>; hasPropsParam: boolean } | undefined {
  const param0 = fn.params[0];

  if (!param0) {
    return undefined;
  }

  if (param0.type === 'Identifier') {
    if (param0.name === 'props') {
      return { propNames: new Set<string>(), hasPropsParam: true };
    }

    return { propNames: new Set([param0.name]), hasPropsParam: false };
  }

  if (param0.type === 'ObjectPattern' || param0.type === 'ArrayPattern') {
    return {
      propNames: new Set(collectPatternBindingNames(param0)),
      hasPropsParam: false,
    };
  }

  if (param0.type === 'AssignmentPattern' && param0.left.type === 'Identifier') {
    return {
      propNames: new Set([param0.left.name]),
      hasPropsParam: false,
    };
  }

  return undefined;
}

function expressionUsesPropsMember(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
): boolean {
  let uses = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (uses) {
      return;
    }

    if (
      node.type === 'MemberExpression' &&
      node.object.type === 'Identifier' &&
      node.object.name === 'props'
    ) {
      uses = true;
    }
  });

  return uses;
}

function expressionUsesAnyIdentifier(
  expr: TSESTree.Expression | TSESTree.PrivateIdentifier,
  names: ReadonlySet<string>,
): boolean {
  let uses = false;

  walkAst(expr as TSESTree.Node, (node) => {
    if (uses) {
      return;
    }

    if (node.type === 'Identifier' && names.has(node.name)) {
      uses = true;
    }
  });

  return uses;
}

type FunctionLike =
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | TSESTree.ArrowFunctionExpression;

function functionBodyRoot(fn: FunctionLike): TSESTree.Node {
  const body = fn.body;

  if (body.type === 'BlockStatement') {
    return body;
  }

  return body as TSESTree.Node;
}

function findInnermostEnclosingFunction(
  program: TSESTree.Program,
  target: TSESTree.Node,
): FunctionLike | undefined {
  const candidates: FunctionLike[] = [];

  walkAst(program, (node) => {
    if (
      node.type !== 'FunctionDeclaration' &&
      node.type !== 'FunctionExpression' &&
      node.type !== 'ArrowFunctionExpression'
    ) {
      return;
    }

    const fn = node as FunctionLike;

    if (containsNode(functionBodyRoot(fn), target)) {
      candidates.push(fn);
    }
  });

  if (candidates.length === 0) {
    return undefined;
  }

  candidates.sort(
    (left, right) =>
      left.range[1] - left.range[0] - (right.range[1] - right.range[0]),
  );

  return candidates[0];
}

function containsNode(ancestor: TSESTree.Node, target: TSESTree.Node): boolean {
  let found = false;

  walkAst(ancestor, (node) => {
    if (node === target) {
      found = true;
    }
  });

  return found;
}

function collectDerivedStateFacts(context: TypeScriptFactDetectorContext): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'useState' && calleeText !== 'React.useState') {
      return;
    }

    const rawInit = node.arguments[0];

    if (!rawInit || rawInit.type === 'SpreadElement') {
      return;
    }

    const init = rawInit as TSESTree.Expression;

    const enclosing = findInnermostEnclosingFunction(context.program, node);

    if (!enclosing) {
      return;
    }

    const bindings = getFirstParamPropBindings(enclosing);

    if (!bindings) {
      return;
    }

    let isDerived = false;

    if (bindings.hasPropsParam && expressionUsesPropsMember(init)) {
      isDerived = true;
    } else if (!bindings.hasPropsParam && bindings.propNames.size > 0) {
      if (expressionUsesAnyIdentifier(init, bindings.propNames)) {
        isDerived = true;
      }
    }

    if (!isDerived) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_DERIVED_STATE,
        node: init,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(init, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}

const INTERACTIVE_JSX_TAGS = new Set([
  'button',
  'a',
  'textarea',
  'select',
  'option',
]);

const INTERACTIVE_ROLES = new Set([
  'button',
  'link',
  'textbox',
  'checkbox',
  'radio',
  'switch',
  'tab',
  'menuitem',
  'menuitemcheckbox',
  'menuitemradio',
  'option',
  'slider',
  'spinbutton',
]);

function getJsxTagName(
  name: TSESTree.JSXOpeningElement['name'],
  sourceText: string,
): string | undefined {
  if (name.type === 'JSXIdentifier') {
    return name.name;
  }

  if (name.type === 'JSXMemberExpression') {
    return getNodeText(name, sourceText);
  }

  return undefined;
}

function getJsxStringAttr(
  opening: TSESTree.JSXOpeningElement,
  attrName: string,
): string | undefined {
  for (const attr of opening.attributes) {
    if (attr.type !== 'JSXAttribute') {
      continue;
    }

    if (attr.name.type !== 'JSXIdentifier' || attr.name.name !== attrName) {
      continue;
    }

    const v = attr.value;

    if (!v) {
      return '';
    }

    if (v.type === 'Literal' && typeof v.value === 'string') {
      return v.value;
    }

    if (v.type === 'JSXExpressionContainer') {
      const ex = v.expression;

      if (ex.type === 'Literal' && typeof ex.value === 'string') {
        return ex.value;
      }
    }

    return '[expression]';
  }

  return undefined;
}

function jsxHasAccessibleNameAttr(opening: TSESTree.JSXOpeningElement): boolean {
  for (const attr of opening.attributes) {
    if (attr.type !== 'JSXAttribute') {
      continue;
    }

    if (attr.name.type !== 'JSXIdentifier') {
      continue;
    }

    const n = attr.name.name;

    if (n === 'aria-label' || n === 'aria-labelledby' || n === 'title') {
      if (!attr.value) {
        return true;
      }

      if (attr.value.type === 'Literal') {
        return String(attr.value.value).trim().length > 0;
      }

      if (attr.value.type === 'JSXExpressionContainer') {
        return true;
      }

      return true;
    }
  }

  return false;
}

function jsxHasNonEmptyTextContent(element: TSESTree.JSXElement): boolean {
  for (const child of element.children) {
    if (child.type === 'JSXText') {
      if (child.value.trim().length > 0) {
        return true;
      }
    }

    if (child.type === 'JSXExpressionContainer') {
      const ex = child.expression;

      if (ex.type === 'Literal' && typeof ex.value === 'string' && ex.value.trim()) {
        return true;
      }
    }

    if (child.type === 'JSXElement' && jsxHasNonEmptyTextContent(child)) {
      return true;
    }
  }

  return false;
}

function shouldCheckAccessibleName(
  opening: TSESTree.JSXOpeningElement,
  sourceText: string,
): boolean {
  const tag = getJsxTagName(opening.name, sourceText);

  if (!tag) {
    return false;
  }

  const lower = tag.toLowerCase();

  if (lower === 'input') {
    const inputType = getJsxStringAttr(opening, 'type');

    if (inputType?.toLowerCase() === 'hidden') {
      return false;
    }

    return true;
  }

  if (INTERACTIVE_JSX_TAGS.has(lower)) {
    return true;
  }

  const role = getJsxStringAttr(opening, 'role');

  if (role && INTERACTIVE_ROLES.has(role.toLowerCase())) {
    return true;
  }

  return false;
}

function collectMissingAccessibleNameFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXElement') {
      return;
    }

    const opening = node.openingElement;

    if (!shouldCheckAccessibleName(opening, context.sourceText)) {
      return;
    }

    if (jsxHasAccessibleNameAttr(opening)) {
      return;
    }

    if (jsxHasNonEmptyTextContent(node)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_A11Y_NAME,
        node: opening.name as TSESTree.Node,
        nodeIds: context.nodeIds,
        props: {
          tag: getJsxTagName(opening.name, context.sourceText),
        },
        text: getNodeText(opening.name as TSESTree.Node, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}

function collectUncontrolledControlledInputFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'JSXElement') {
      return;
    }

    const opening = node.openingElement;
    const tag = getJsxTagName(opening.name, context.sourceText);

    if (!tag || tag.toLowerCase() !== 'input') {
      return;
    }

    let hasValue = false;
    let hasDefaultValue = false;

    for (const attr of opening.attributes) {
      if (attr.type !== 'JSXAttribute') {
        continue;
      }

      if (attr.name.type !== 'JSXIdentifier') {
        continue;
      }

      if (attr.name.name === 'value') {
        hasValue = true;
      }

      if (attr.name.name === 'defaultValue') {
        hasDefaultValue = true;
      }
    }

    if (!hasValue || !hasDefaultValue) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'function',
        kind: FACT_UNCONTROLLED,
        node: opening.name as TSESTree.Node,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(opening.name as TSESTree.Node, context.sourceText),
      }),
    );
  });

  return dedupeFactsByRange(facts);
}
