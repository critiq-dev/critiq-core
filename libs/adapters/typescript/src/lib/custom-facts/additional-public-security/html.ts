import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getObjectProperty,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { isRequestDerivedExpression } from './analysis';
import { FACT_KINDS, responseSinkNames } from './constants';
import {
  getLiteralString,
  getMemberPropertyName,
  isHtmlLikeText,
  unwrapExpression,
} from './utils';
import { isTrustedHtmlSanitizerCall } from '../substrate/html-sanitizers';
import { trustBoundaryTemplateCompilerCallees } from '../../trust-boundary';

const dangerousHtmlInsertionMethods = new Set(['insertAdjacentHTML']);
const dangerousDocumentMethods = new Set(['write', 'writeln']);

function isTrustedHtmlCall(
  expression: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  return isTrustedHtmlSanitizerCall(expression, sourceText);
}

function isTrustedHtmlExpression(
  node: TSESTree.Expression | undefined,
  trustedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  const expression = unwrapExpression(node);

  if (!expression) {
    return false;
  }

  switch (expression.type) {
    case 'Literal':
      return typeof expression.value === 'string';
    case 'Identifier':
      return trustedNames.has(expression.name);
    case 'TemplateLiteral':
      return expression.expressions.every((candidate) =>
        isTrustedHtmlExpression(candidate, trustedNames, sourceText),
      );
    case 'BinaryExpression':
      return (
        expression.operator === '+' &&
        isTrustedHtmlExpression(expression.left, trustedNames, sourceText) &&
        isTrustedHtmlExpression(expression.right, trustedNames, sourceText)
      );
    case 'CallExpression':
      return isTrustedHtmlCall(expression, sourceText);
    case 'ConditionalExpression':
      return (
        isTrustedHtmlExpression(
          expression.consequent,
          trustedNames,
          sourceText,
        ) &&
        isTrustedHtmlExpression(expression.alternate, trustedNames, sourceText)
      );
    case 'LogicalExpression':
      return (
        isTrustedHtmlExpression(expression.left, trustedNames, sourceText) &&
        isTrustedHtmlExpression(expression.right, trustedNames, sourceText)
      );
    default:
      return false;
  }
}

function collectTrustedHtmlNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const trustedNames = new Set<string>();
  let changed = true;

  while (changed) {
    changed = false;

    walkAst(context.program, (node) => {
      if (node.type === 'VariableDeclarator') {
        if (node.id.type !== 'Identifier' || !node.init) {
          return;
        }

        if (
          isTrustedHtmlExpression(node.init, trustedNames, context.sourceText) &&
          !trustedNames.has(node.id.name)
        ) {
          trustedNames.add(node.id.name);
          changed = true;
        }

        return;
      }

      if (
        node.type === 'AssignmentExpression' &&
        node.left.type === 'Identifier' &&
        isTrustedHtmlExpression(node.right, trustedNames, context.sourceText) &&
        !trustedNames.has(node.left.name)
      ) {
        trustedNames.add(node.left.name);
        changed = true;
      }
    });
  }

  return trustedNames;
}

function collectExpressionBindings(
  context: TypeScriptFactDetectorContext,
): Map<string, TSESTree.Expression> {
  const bindings = new Map<string, TSESTree.Expression>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      const expression = unwrapExpression(node.init);

      if (expression) {
        bindings.set(node.id.name, expression);
      }

      return;
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'Identifier'
    ) {
      const expression = unwrapExpression(node.right);

      if (expression) {
        bindings.set(node.left.name, expression);
      }
    }
  });

  return bindings;
}

function extractDangerouslySetInnerHtmlValue(
  expression: TSESTree.Expression | undefined,
  expressionBindings: ReadonlyMap<string, TSESTree.Expression>,
  depth = 0,
): TSESTree.Expression | undefined {
  if (!expression || depth > 1) {
    return undefined;
  }

  const unwrapped = unwrapExpression(expression);

  if (!unwrapped) {
    return undefined;
  }

  if (unwrapped.type === 'Identifier') {
    return extractDangerouslySetInnerHtmlValue(
      expressionBindings.get(unwrapped.name),
      expressionBindings,
      depth + 1,
    );
  }

  if (unwrapped.type !== 'ObjectExpression') {
    return undefined;
  }

  const htmlProperty = getObjectProperty(unwrapped, '__html');

  if (!htmlProperty) {
    return undefined;
  }

  return unwrapExpression(htmlProperty.value as TSESTree.Expression);
}

function hasUnsafeRequestHtmlExpression(
  expression: TSESTree.Expression | undefined,
  taintedNames: ReadonlySet<string>,
  trustedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  return Boolean(
    expression &&
      isRequestDerivedExpression(expression, taintedNames, sourceText) &&
      !isTrustedHtmlExpression(expression, trustedNames, sourceText),
  );
}

export function collectHttpResponseFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const trustedNames = collectTrustedHtmlNames(context);
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const payload = unwrapExpression(
      node.arguments[0] as TSESTree.Expression | undefined,
    );

    if (
      !calleeText ||
      !responseSinkNames.has(calleeText) ||
      !payload ||
      payload.type === 'ArrayExpression' ||
      payload.type === 'ObjectExpression' ||
      !hasUnsafeRequestHtmlExpression(
        payload,
        taintedNames,
        trustedNames,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.unsanitizedHttpResponse,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

export function collectHtmlOutputFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const trustedNames = collectTrustedHtmlNames(context);
  const expressionBindings = collectExpressionBindings(context);
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'TemplateLiteral') {
      const literalText = node.quasis.map((quasi) => quasi.value.raw).join('');

      if (
        isHtmlLikeText(literalText) &&
        node.expressions.some((expression) =>
          hasUnsafeRequestHtmlExpression(
            expression,
            taintedNames,
            trustedNames,
            context.sourceText,
          ),
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.rawHtmlUsingUserInput,
            node,
            nodeIds: context.nodeIds,
            text: excerptFor(node, context.sourceText),
          }),
        );
      }

      return;
    }

    if (node.type === 'AssignmentExpression') {
      if (node.left.type !== 'MemberExpression') {
        return;
      }

      const propertyName = getMemberPropertyName(node.left);
      const value = unwrapExpression(node.right);

      if (
        !value ||
        (propertyName !== 'innerHTML' && propertyName !== 'outerHTML') ||
        isTrustedHtmlExpression(value, trustedNames, context.sourceText)
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind:
            propertyName === 'innerHTML'
              ? FACT_KINDS.noInnerHtmlAssignment
              : FACT_KINDS.dangerousInsertHtml,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: propertyName,
          },
          text: excerptFor(node, context.sourceText),
        }),
      );

      return;
    }

    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (calleeText && /(?:^|\.)(replace|replaceAll)$/u.test(calleeText)) {
        const matchLiteral = getLiteralString(
          node.arguments[0] as TSESTree.Expression,
        );
        const replacementLiteral = getLiteralString(
          node.arguments[1] as TSESTree.Expression,
        );

        if (
          ['"', "'", '&', '<', '>'].includes(matchLiteral ?? '') &&
          /&(lt|gt|apos|quot|amp);/iu.test(replacementLiteral ?? '')
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.manualHtmlSanitization,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }

        return;
      }

      if (calleeText && trustBoundaryTemplateCompilerCallees.has(calleeText)) {
        const options = unwrapExpression(
          node.arguments[1] as TSESTree.Expression | undefined,
        );
        const noEscape =
          options?.type === 'ObjectExpression'
            ? getObjectProperty(options, 'noEscape')
            : undefined;

        if (
          noEscape?.value.type === 'Literal' &&
          noEscape.value.value === true
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.handlebarsNoEscape,
              node,
              nodeIds: context.nodeIds,
              props: {
                sink: calleeText,
              },
              text: calleeText,
            }),
          );
        }

        return;
      }

      if (
        node.callee.type === 'MemberExpression' &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'document'
      ) {
        const propertyName = getMemberPropertyName(node.callee);

        if (propertyName && dangerousDocumentMethods.has(propertyName)) {
          const hasUnsafeArgument = node.arguments.some((argument) => {
            if (argument.type === 'SpreadElement') {
              return true;
            }

            const expression = unwrapExpression(argument);

            return Boolean(
              expression &&
                !isTrustedHtmlExpression(
                  expression,
                  trustedNames,
                  context.sourceText,
                ),
            );
          });

          if (hasUnsafeArgument) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.dangerousInsertHtml,
                node,
                nodeIds: context.nodeIds,
                props: {
                  sink: calleeText,
                },
                text: calleeText,
              }),
            );
          }
        }

        return;
      }

      if (node.callee.type !== 'MemberExpression') {
        return;
      }

      const propertyName = getMemberPropertyName(node.callee);

      if (
        !propertyName ||
        !dangerousHtmlInsertionMethods.has(propertyName)
      ) {
        return;
      }

      const payload = unwrapExpression(
        node.arguments[1] as TSESTree.Expression | undefined,
      );

      if (
        payload &&
        !isTrustedHtmlExpression(payload, trustedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.dangerousInsertHtml,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }

      return;
    }

    if (node.type === 'JSXAttribute') {
      if (
        node.name.type !== 'JSXIdentifier' ||
        node.name.name !== 'dangerouslySetInnerHTML' ||
        !node.value ||
        node.value.type !== 'JSXExpressionContainer'
      ) {
        return;
      }

      const htmlValue = extractDangerouslySetInnerHtmlValue(
        unwrapExpression(node.value.expression),
        expressionBindings,
      );

      if (
        htmlValue &&
        !isTrustedHtmlExpression(htmlValue, trustedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.dangerouslySetInnerHtml,
            node,
            nodeIds: context.nodeIds,
            text: excerptFor(node, context.sourceText),
          }),
        );
      }
    }
  });

  return facts;
}
