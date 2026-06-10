import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getMemberPropertyName } from './additional-public-security/property-names';
import { unwrapExpression } from './additional-public-security/unwrap-expression';
import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  walkAst,
  walkAstWithAncestors,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const FACT_KINDS = {
  withStatement: 'security.with-statement',
  argumentsCalleeOrCaller: 'security.arguments-callee-or-caller',
  javascriptUrl: 'security.javascript-url',
  nativePrototypeExtension: 'security.native-prototype-extension',
  globalNativeReassignment: 'security.global-native-reassignment',
  throwLiteral: 'security.throw-literal',
  alertConfirmPrompt: 'security.alert-confirm-prompt',
  processExit: 'runtime.process-exit',
  processExitControlFlow: 'runtime.process-exit-control-flow',
  unsafeDirnamePathConcat: 'security.unsafe-dirname-path-concat',
} as const;

const nativeConstructorNames = new Set([
  'Array',
  'ArrayBuffer',
  'BigInt',
  'Boolean',
  'DataView',
  'Date',
  'Error',
  'Float32Array',
  'Float64Array',
  'Function',
  'Int16Array',
  'Int32Array',
  'Int8Array',
  'Map',
  'Number',
  'Object',
  'Promise',
  'RegExp',
  'Set',
  'String',
  'Symbol',
  'Uint16Array',
  'Uint32Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'WeakMap',
  'WeakSet',
]);

const globalNativeBindingNames = new Set([
  'Array',
  'Boolean',
  'Date',
  'decodeURI',
  'decodeURIComponent',
  'encodeURI',
  'encodeURIComponent',
  'Error',
  'escape',
  'EvalError',
  'eval',
  'Infinity',
  'isFinite',
  'isNaN',
  'JSON',
  'Math',
  'NaN',
  'Number',
  'Object',
  'parseFloat',
  'parseInt',
  'RangeError',
  'ReferenceError',
  'RegExp',
  'String',
  'Symbol',
  'SyntaxError',
  'TypeError',
  'undefined',
  'unescape',
  'URIError',
]);

const dialogCalleeNames = new Set(['alert', 'confirm', 'prompt']);

const errorConstructorNames = new Set([
  'Error',
  'EvalError',
  'RangeError',
  'ReferenceError',
  'SyntaxError',
  'TypeError',
  'URIError',
  'AggregateError',
]);

const javascriptUrlPattern = /^\s*javascript:/iu;

function containsDirnameOrFilename(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  return /\b__dirname\b/u.test(text) || /\b__filename\b/u.test(text);
}

function isJavascriptUrlLiteral(value: string): boolean {
  return javascriptUrlPattern.test(value.trim());
}

function literalStringValue(
  node: TSESTree.Node | null | undefined,
): string | undefined {
  if (node?.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  return node.value;
}

function templateLiteralStartsWithJavascriptUrl(
  node: TSESTree.TemplateLiteral,
): boolean {
  const firstQuasi = node.quasis[0]?.value.cooked ?? node.quasis[0]?.value.raw;

  return Boolean(firstQuasi && isJavascriptUrlLiteral(firstQuasi));
}

function isNativePrototypeMember(
  memberExpression: TSESTree.MemberExpression,
): string | undefined {
  if (
    memberExpression.object.type !== 'MemberExpression' ||
    memberExpression.object.computed
  ) {
    return undefined;
  }

  const prototypeProperty = getMemberPropertyName(memberExpression.object);

  if (prototypeProperty !== 'prototype') {
    return undefined;
  }

  const constructorNode = memberExpression.object.object;

  if (constructorNode.type !== 'Identifier') {
    return undefined;
  }

  if (!nativeConstructorNames.has(constructorNode.name)) {
    return undefined;
  }

  return constructorNode.name;
}

function isThrowingLiteralValue(
  argument: TSESTree.Expression | undefined,
): boolean {
  const expression = unwrapExpression(argument);

  if (!expression) {
    return false;
  }

  switch (expression.type) {
    case 'Literal':
    case 'TemplateLiteral':
    case 'ArrayExpression':
    case 'ObjectExpression':
      return true;
    case 'UnaryExpression':
      return expression.operator === 'void' || expression.operator === '-';
    case 'NewExpression': {
      const calleeName =
        expression.callee.type === 'Identifier'
          ? expression.callee.name
          : undefined;

      return !calleeName || !errorConstructorNames.has(calleeName);
    }
    case 'CallExpression': {
      const calleeText =
        expression.callee.type === 'Identifier'
          ? expression.callee.name
          : undefined;

      return !calleeText || !errorConstructorNames.has(calleeText);
    }
    case 'Identifier':
      return false;
    default:
      return true;
  }
}

function isDialogCall(calleeText: string | undefined): boolean {
  if (!calleeText) {
    return false;
  }

  const leafName = calleeText.split('.').at(-1);

  return Boolean(leafName && dialogCalleeNames.has(leafName));
}

function isProcessExitCall(calleeText: string | undefined): boolean {
  return calleeText === 'process.exit';
}

function collectWithStatementFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'WithStatement') {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.withStatement,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectArgumentsCalleeFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'MemberExpression' ||
      node.object.type !== 'Identifier' ||
      node.object.name !== 'arguments' ||
      node.computed
    ) {
      return;
    }

    const propertyName = getMemberPropertyName(node);

    if (propertyName !== 'callee' && propertyName !== 'caller') {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.argumentsCalleeOrCaller,
        node,
        nodeIds: context.nodeIds,
        props: {
          property: propertyName,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function isJsxUrlAttributeValue(
  ancestors: readonly TSESTree.Node[],
): boolean {
  return ancestors.some((ancestor) => ancestor.type === 'JSXAttribute');
}

function collectJavascriptUrlFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type === 'Literal') {
      if (isJsxUrlAttributeValue(ancestors)) {
        return;
      }

      const literalValue = literalStringValue(node);

      if (!literalValue || !isJavascriptUrlLiteral(literalValue)) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.javascriptUrl,
          node,
          nodeIds: context.nodeIds,
          text: excerptFor(node, context.sourceText),
        }),
      );

      return;
    }

    if (node.type === 'TemplateLiteral') {
      if (isJsxUrlAttributeValue(ancestors)) {
        return;
      }

      if (!templateLiteralStartsWithJavascriptUrl(node)) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.javascriptUrl,
          node,
          nodeIds: context.nodeIds,
          text: excerptFor(node, context.sourceText),
        }),
      );

      return;
    }

    if (node.type !== 'JSXAttribute' || node.name.type !== 'JSXIdentifier') {
      return;
    }

    if (node.name.name !== 'href' && node.name.name !== 'src') {
      return;
    }

    const value = node.value;

    if (!value) {
      return;
    }

    if (value.type === 'Literal') {
      const literalValue = literalStringValue(value);

      if (literalValue && isJavascriptUrlLiteral(literalValue)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.javascriptUrl,
            node: value,
            nodeIds: context.nodeIds,
            props: {
              attribute: node.name.name,
            },
            text: excerptFor(value, context.sourceText),
          }),
        );
      }

      return;
    }

    if (value.type === 'JSXExpressionContainer') {
      const expression = unwrapExpression(value.expression);

      if (expression?.type === 'Literal') {
        const literalValue = literalStringValue(expression);

        if (literalValue && isJavascriptUrlLiteral(literalValue)) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.javascriptUrl,
              node: expression,
              nodeIds: context.nodeIds,
              props: {
                attribute: node.name.name,
              },
              text: excerptFor(expression, context.sourceText),
            }),
          );
        }
      }
    }
  });

  return facts;
}

function collectNativePrototypeExtensionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'MemberExpression'
    ) {
      return;
    }

    const memberExpression = node.left;

    const constructorName = isNativePrototypeMember(memberExpression);

    if (!constructorName) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.nativePrototypeExtension,
        node,
        nodeIds: context.nodeIds,
        props: {
          constructor: constructorName,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectGlobalNativeReassignmentFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'AssignmentExpression') {
      return;
    }

    if (node.left.type !== 'Identifier') {
      return;
    }

    if (!globalNativeBindingNames.has(node.left.name)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.globalNativeReassignment,
        node,
        nodeIds: context.nodeIds,
        props: {
          binding: node.left.name,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectThrowLiteralFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'ThrowStatement') {
      return;
    }

    const argument = unwrapExpression(node.argument);

    if (!argument || !isThrowingLiteralValue(argument)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.throwLiteral,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectAlertConfirmPromptFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!isDialogCall(calleeText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.alertConfirmPrompt,
        node,
        nodeIds: context.nodeIds,
        props: {
          callee: calleeText,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectProcessExitFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!isProcessExitCall(calleeText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.processExit,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectProcessExitControlFlowFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!isProcessExitCall(calleeText)) {
      return;
    }

    let parent: TSESTree.Node | undefined;

    for (let index = ancestors.length - 1; index >= 0; index -= 1) {
      const ancestor = ancestors[index];
      if (
        ancestor.type === 'TryStatement' ||
        ancestor.type === 'FunctionDeclaration' ||
        ancestor.type === 'FunctionExpression' ||
        ancestor.type === 'ArrowFunctionExpression' ||
        ancestor.type === 'Program'
      ) {
        parent = ancestor;
        break;
      }
    }

    if (!parent) {
      return;
    }

    if (parent.type === 'TryStatement' && parent.finalizer) {
      let insideFinally = false;

      walkAst(parent.finalizer, (inner) => {
        if (inner === node) {
          insideFinally = true;
        }
      });

      if (insideFinally) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.processExitControlFlow,
            node,
            nodeIds: context.nodeIds,
            text: excerptFor(node, context.sourceText),
            props: {
              context: 'finally',
              callee: calleeText,
            },
          }),
        );

        return;
      }
    }

    if (parent.type === 'TryStatement' || parent.type === 'FunctionDeclaration' ||
        parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression') {

      const body = parent.type === 'TryStatement'
        ? parent.block
        : (parent as TSESTree.FunctionLike).body;

      if (!body || body.type !== 'BlockStatement') {
        return;
      }

      const bodyStatements = body.body;
      let nodeIndex = -1;

      for (let index = 0; index < bodyStatements.length; index += 1) {
        const stmt = bodyStatements[index];
        let found = false;
        walkAst(stmt, (inner) => {
          if (inner === node) {
            found = true;
          }
        });
        if (found) {
          nodeIndex = index;
          break;
        }
      }

      if (nodeIndex >= 0 && nodeIndex < bodyStatements.length - 1) {
        const nextStatement = bodyStatements[nodeIndex + 1];

        let hasReachableCode = true;

        if (
          nextStatement.type === 'ReturnStatement' ||
          nextStatement.type === 'ThrowStatement'
        ) {
          hasReachableCode = false;
        }

        if (hasReachableCode) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.processExitControlFlow,
              node,
              nodeIds: context.nodeIds,
              text: excerptFor(node, context.sourceText),
              props: {
                context: 'reachable-code-after-exit',
                callee: calleeText,
              },
            }),
          );
        }
      }
    }
  });

  return facts;
}

function collectUnsafeDirnamePathConcatFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'BinaryExpression' && node.operator === '+') {
      const expressionText = getNodeText(node, context.sourceText);

      if (!containsDirnameOrFilename(expressionText)) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.unsafeDirnamePathConcat,
          node,
          nodeIds: context.nodeIds,
          text: excerptFor(node, context.sourceText),
        }),
      );

      return;
    }

    if (node.type !== 'TemplateLiteral') {
      return;
    }

    const templateText = getNodeText(node, context.sourceText);

    if (!containsDirnameOrFilename(templateText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.unsafeDirnamePathConcat,
        node,
        nodeIds: context.nodeIds,
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

/** Collects language-level security and Node runtime facts for TypeScript sources. */
export const collectTypescriptRuntimeSecurityFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => [
  ...collectWithStatementFacts(context),
  ...collectArgumentsCalleeFacts(context),
  ...collectJavascriptUrlFacts(context),
  ...collectNativePrototypeExtensionFacts(context),
  ...collectGlobalNativeReassignmentFacts(context),
  ...collectThrowLiteralFacts(context),
  ...collectAlertConfirmPromptFacts(context),
  ...collectProcessExitFacts(context),
  ...collectProcessExitControlFlowFacts(context),
  ...collectUnsafeDirnamePathConcatFacts(context),
];
