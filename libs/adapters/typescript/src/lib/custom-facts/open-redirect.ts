import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  isNode,
  type TypeScriptFactDetectorContext,
  walkAst,
} from './shared';
import { isSafeRedirectWrapperCall } from './outbound-network';

const redirectSinkCallNames = new Set([
  'NextResponse.redirect',
  'Response.redirect',
  'location.assign',
  'redirect',
  'reply.redirect',
  'res.redirect',
  'router.push',
  'router.replace',
]);

const redirectSinkAssignmentPattern =
  /(^|\.)(window\.)?location(\.href)?$/u;

const redirectSourceGetterPattern =
  /\b(?:searchParams|formData|query|params|body|headers|cookies)\.get\(\s*['"][^'"]+['"]\s*\)/u;

const redirectSourceMemberPattern =
  /\b(?:req|request|ctx|context|router|nextUrl)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*|\[['"][^'"]+['"]\])*(?:\.(?:query|params|body|headers|cookies|searchParams|formData)\b|\[['"](?:query|params|body|headers|cookies|searchParams|formData)['"]\])/u;

const redirectIdentifierPattern =
  /^(callbackUrl|continue|dest|destination|next|redirect|returnTo|returnUrl)$/iu;

interface TaintedAssignment {
  target: string;
  value: TSESTree.Expression;
}

interface SinkCandidate {
  node: TSESTree.CallExpression | TSESTree.AssignmentExpression;
  value: TSESTree.Expression;
  sink: string;
}

function isFunctionLike(node: TSESTree.Node): node is
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression {
  return (
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression'
  );
}

function isScopeRoot(
  node: TSESTree.Node,
): node is
  | TSESTree.Program
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression {
  return node.type === 'Program' || isFunctionLike(node);
}

function rootBodyNodes(
  root: TSESTree.Program | TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression,
): TSESTree.Node[] {
  if (root.type === 'Program') {
    return root.body;
  }

  if (root.body.type === 'BlockStatement') {
    return root.body.body;
  }

  return [root.body];
}

function collectScopedNodes(root: TSESTree.Program | TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression): TSESTree.Node[] {
  const nodes: TSESTree.Node[] = [];

  const visit = (node: TSESTree.Node): void => {
    nodes.push(node);

    for (const value of Object.values(node as unknown as Record<string, unknown>)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (isNode(entry)) {
            if (isFunctionLike(entry) && entry !== root) {
              continue;
            }

            visit(entry);
          }
        }

        continue;
      }

      if (isNode(value)) {
        if (isFunctionLike(value) && value !== root) {
          continue;
        }

        visit(value);
      }
    }
  };

  for (const node of rootBodyNodes(root)) {
    visit(node);
  }

  return nodes;
}

function expressionText(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!expression) {
    return undefined;
  }

  return getNodeText(expression, sourceText);
}

function containsTaintedIdentifier(
  text: string | undefined,
  taintedNames: ReadonlySet<string>,
): boolean {
  if (!text) {
    return false;
  }

  return [...taintedNames].some((name) =>
    new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'u').test(text),
  );
}

function isSafeWrapperCall(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  return isSafeRedirectWrapperCall(expression, sourceText);
}

function isInlinePathNormalizationExpression(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): boolean {
  if (!expression) {
    return false;
  }

  if (expression.type === 'ConditionalExpression') {
    const testText = expressionText(expression.test, sourceText);

    return (
      Boolean(testText && /\.startsWith\(\s*['"]\/['"]\s*\)/u.test(testText)) &&
      isPathLiteralExpression(expression.consequent) !==
        isPathLiteralExpression(expression.alternate)
    );
  }

  if (expression.type === 'LogicalExpression' && expression.operator === '||') {
    const leftText = expressionText(expression.left, sourceText);
    const rightText = expressionText(expression.right, sourceText);

    return (
      Boolean(leftText && /\.startsWith\(\s*['"]\/['"]\s*\)/u.test(leftText)) &&
      isPathLiteralExpression(expression.right) &&
      Boolean(rightText)
    );
  }

  return false;
}

function isPathLiteralExpression(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): boolean {
  return Boolean(
    expression &&
      expression.type === 'Literal' &&
      typeof expression.value === 'string' &&
      expression.value.startsWith('/'),
  );
}

function isLikelyRedirectSourceExpression(
  expression: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!expression) {
    return false;
  }

  if (expression.type === 'Identifier') {
    return (
      taintedNames.has(expression.name) || redirectIdentifierPattern.test(expression.name)
    );
  }

  if (expression.type === 'CallExpression') {
    if (isSafeWrapperCall(expression, sourceText)) {
      return false;
    }

    const calleeText = getCalleeText(expression.callee, sourceText);
    const firstArgument = expression.arguments.find(
      (argument): argument is TSESTree.Expression =>
        argument.type !== 'SpreadElement',
    );
    const calleeTextString = calleeText ?? '';
    const callText = expressionText(expression, sourceText);

    if (
      /(?:searchParams|formData|query|params|body|headers|cookies)\.get$/u.test(
        calleeTextString,
      ) ||
      redirectSourceGetterPattern.test(callText ?? '')
    ) {
      return true;
    }

    return firstArgument
      ? isLikelyRedirectSourceExpression(firstArgument, taintedNames, sourceText)
      : false;
  }

  if (expression.type === 'MemberExpression') {
    const text = expressionText(expression, sourceText);

    return (
      Boolean(text && redirectSourceMemberPattern.test(text)) ||
      (expression.object.type === 'Identifier' &&
        taintedNames.has(expression.object.name))
    );
  }

  if (expression.type === 'ConditionalExpression') {
    return (
      isLikelyRedirectSourceExpression(expression.consequent, taintedNames, sourceText) ||
      isLikelyRedirectSourceExpression(expression.alternate, taintedNames, sourceText)
    );
  }

  if (expression.type === 'LogicalExpression') {
    return (
      isLikelyRedirectSourceExpression(expression.left, taintedNames, sourceText) ||
      isLikelyRedirectSourceExpression(expression.right, taintedNames, sourceText)
    );
  }

  if (expression.type === 'TemplateLiteral') {
    return containsTaintedIdentifier(expressionText(expression, sourceText), taintedNames);
  }

  if (expression.type === 'Literal') {
    return false;
  }

  const text = expressionText(expression, sourceText);

  return (
    containsTaintedIdentifier(text, taintedNames) ||
    Boolean(text && redirectSourceMemberPattern.test(text)) ||
    Boolean(text && redirectSourceGetterPattern.test(text))
  );
}

function collectTaintedAssignments(
  nodes: ReadonlyArray<TSESTree.Node>,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): TaintedAssignment[] {
  const assignments: TaintedAssignment[] = [];

  for (const node of nodes) {
    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      node.init &&
      isLikelyRedirectSourceExpression(node.init, taintedNames, sourceText)
    ) {
      assignments.push({
        target: node.id.name,
        value: node.init,
      });
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'Identifier' &&
      isLikelyRedirectSourceExpression(node.right, taintedNames, sourceText)
    ) {
      assignments.push({
        target: node.left.name,
        value: node.right,
      });
    }
  }

  return assignments;
}

function collectSinkCandidates(
  nodes: ReadonlyArray<TSESTree.Node>,
  sourceText: string,
): SinkCandidate[] {
  const sinks: SinkCandidate[] = [];

  for (const node of nodes) {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, sourceText);

      if (!calleeText || !redirectSinkCallNames.has(calleeText)) {
        continue;
      }

      const value = node.arguments.find(
        (argument): argument is TSESTree.Expression =>
          argument.type !== 'SpreadElement',
      );

      if (!value) {
        continue;
      }

      sinks.push({
        node,
        sink: calleeText,
        value,
      });
    }

    if (node.type === 'AssignmentExpression') {
      const leftText = expressionText(node.left, sourceText);

      if (!leftText || !redirectSinkAssignmentPattern.test(leftText)) {
        continue;
      }

      sinks.push({
        node,
        sink: leftText,
        value: node.right,
      });
    }
  }

  return sinks;
}

function collectScopeFacts(
  root: TSESTree.Program | TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression,
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const nodes = collectScopedNodes(root);
  const taintedNames = new Set<string>();

  let changed = true;

  while (changed) {
    changed = false;
    const discovered = collectTaintedAssignments(nodes, taintedNames, context.sourceText);

    for (const assignment of discovered) {
      if (taintedNames.has(assignment.target)) {
        continue;
      }

      taintedNames.add(assignment.target);
      changed = true;
    }
  }

  const facts: ObservedFact[] = [];

  for (const sink of collectSinkCandidates(nodes, context.sourceText)) {
    const valueText = expressionText(sink.value, context.sourceText);

    if (
      isSafeWrapperCall(sink.value, context.sourceText) ||
      isInlinePathNormalizationExpression(sink.value, context.sourceText)
    ) {
      continue;
    }

    if (!isLikelyRedirectSourceExpression(sink.value, taintedNames, context.sourceText)) {
      continue;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'security.open-redirect',
        node: sink.node,
        nodeIds: context.nodeIds,
        props: {
          sink: sink.sink,
          source: valueText,
        },
        text: expressionText(sink.node, context.sourceText),
      }),
    );
  }

  return facts;
}

export function collectOpenRedirectFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const scopeRoots: Array<
    | TSESTree.Program
    | TSESTree.ArrowFunctionExpression
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
  > = [];

  walkAst(context.program, (node) => {
    if (isScopeRoot(node)) {
      scopeRoots.push(node);
    }
  });

  const facts: ObservedFact[] = [];

  for (const root of scopeRoots) {
    facts.push(...collectScopeFacts(root, context));
  }

  const uniqueFacts = new Map<string, ObservedFact>();

  for (const fact of facts) {
    uniqueFacts.set(fact.id, fact);
  }

  return [...uniqueFacts.values()];
}
