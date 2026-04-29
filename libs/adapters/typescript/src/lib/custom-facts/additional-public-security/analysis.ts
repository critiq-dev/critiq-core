import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getNodeText,
  looksSensitiveIdentifier,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { requestSourcePattern, sensitiveWritePattern } from './constants';
import { getLiteralString, normalizeText } from './utils';

export type FunctionLikeNode =
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression;

const validationWrapperPattern =
  /^(?:allowlist|assert|check|sanitize|validate|verify)/iu;

function leafCalleeName(text: string | undefined): string | undefined {
  if (!text) {
    return undefined;
  }

  return text
    .split('.')
    .at(-1)
    ?.replace(/\?$/u, '')
    .replace(/^#/u, '');
}

export function isValidationLikeCall(
  node: TSESTree.CallExpression | null | undefined,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  const calleeName = leafCalleeName(getNodeText(node.callee, sourceText));

  return Boolean(calleeName && validationWrapperPattern.test(calleeName));
}

export function isRequestDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return taintedNames.has(node.name);
  }

  if (node.type === 'CallExpression' && isValidationLikeCall(node, sourceText)) {
    return false;
  }

  const text = normalizeText(getNodeText(node, sourceText));

  if (text.length > 0 && requestSourcePattern.test(text)) {
    return true;
  }

  switch (node.type) {
    case 'ArrayExpression':
      return node.elements.some((element) =>
        element
          ? isRequestDerivedExpression(element, taintedNames, sourceText)
          : false,
      );
    case 'AssignmentExpression':
    case 'BinaryExpression':
    case 'LogicalExpression':
      return (
        isRequestDerivedExpression(node.left, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.right, taintedNames, sourceText)
      );
    case 'AwaitExpression':
    case 'UnaryExpression':
      return isRequestDerivedExpression(
        node.argument,
        taintedNames,
        sourceText,
      );
    case 'CallExpression':
      return node.arguments.some((argument) =>
        isRequestDerivedExpression(argument, taintedNames, sourceText),
      );
    case 'NewExpression':
      return node.arguments.some((argument) =>
        isRequestDerivedExpression(argument, taintedNames, sourceText),
      );
    case 'ChainExpression':
      return isRequestDerivedExpression(
        node.expression,
        taintedNames,
        sourceText,
      );
    case 'ConditionalExpression':
      return (
        isRequestDerivedExpression(node.test, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.consequent, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.alternate, taintedNames, sourceText)
      );
    case 'MemberExpression':
      return requestSourcePattern.test(text);
    case 'ObjectExpression':
      return node.properties.some((property) => {
        if (property.type === 'Property') {
          return (
            isRequestDerivedExpression(
              property.key,
              taintedNames,
              sourceText,
            ) ||
            isRequestDerivedExpression(property.value, taintedNames, sourceText)
          );
        }

        return isRequestDerivedExpression(
          property.argument,
          taintedNames,
          sourceText,
        );
      });
    case 'TemplateLiteral':
      return node.expressions.some((expression) =>
        isRequestDerivedExpression(expression, taintedNames, sourceText),
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isRequestDerivedExpression(
        node.expression,
        taintedNames,
        sourceText,
      );
    default:
      return false;
  }
}

export function collectRequestDerivedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const taintedNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (
        isRequestDerivedExpression(node.init, taintedNames, context.sourceText)
      ) {
        taintedNames.add(node.id.name);
      }

      return;
    }

    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'Identifier'
    ) {
      return;
    }

    if (
      isRequestDerivedExpression(node.right, taintedNames, context.sourceText)
    ) {
      taintedNames.add(node.left.name);
    }
  });

  return taintedNames;
}

export function collectSensitiveSignals(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string[] {
  const signals = new Set<string>();

  const visit = (
    candidate: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  ) => {
    if (!candidate) {
      return;
    }

    if (candidate.type === 'PrivateIdentifier') {
      if (looksSensitiveIdentifier(candidate.name)) {
        signals.add(candidate.name);
      }
      return;
    }

    if (candidate.type === 'Identifier') {
      if (looksSensitiveIdentifier(candidate.name)) {
        signals.add(candidate.name);
      }
      return;
    }

    if (candidate.type === 'Literal' && typeof candidate.value === 'string') {
      if (sensitiveWritePattern.test(candidate.value)) {
        signals.add(candidate.value);
      }
      return;
    }

    if (candidate.type === 'MemberExpression') {
      const text = getNodeText(candidate, sourceText);

      if (looksSensitiveIdentifier(text)) {
        signals.add(text ?? 'sensitive');
      }
    }

    if (candidate.type === 'Property') {
      const keyText = getNodeText(candidate.key, sourceText);

      if (looksSensitiveIdentifier(keyText)) {
        signals.add(keyText ?? 'sensitive');
      }
    }

    for (const value of Object.values(candidate)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (entry && typeof entry === 'object' && 'type' in entry) {
            visit(entry as TSESTree.Node);
          }
        }

        continue;
      }

      if (value && typeof value === 'object' && 'type' in value) {
        visit(value as TSESTree.Node);
      }
    }
  };

  visit(node);

  return [...signals].sort((left, right) => left.localeCompare(right));
}

export function resolveFunctionBindings(
  context: TypeScriptFactDetectorContext,
): Map<string, FunctionLikeNode> {
  const bindings = new Map<string, FunctionLikeNode>();

  walkAst(context.program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      bindings.set(node.id.name, node);
      return;
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      node.init &&
      (node.init.type === 'ArrowFunctionExpression' ||
        node.init.type === 'FunctionExpression')
    ) {
      bindings.set(node.id.name, node.init);
    }
  });

  return bindings;
}

export function resolveFunctionLike(
  node:
    | TSESTree.Expression
    | TSESTree.SpreadElement
    | TSESTree.PrivateIdentifier
    | undefined,
  bindings: ReadonlyMap<string, FunctionLikeNode>,
): FunctionLikeNode | undefined {
  if (
    !node ||
    node.type === 'SpreadElement' ||
    node.type === 'PrivateIdentifier'
  ) {
    return undefined;
  }

  if (
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'FunctionExpression'
  ) {
    return node;
  }

  if (node.type === 'Identifier') {
    return bindings.get(node.name);
  }

  return undefined;
}

export function hasOriginCheck(
  handler: FunctionLikeNode,
  sourceText: string,
): boolean {
  const firstParam = handler.params[0];

  if (!firstParam || firstParam.type !== 'Identifier') {
    return false;
  }

  const originText = `${firstParam.name}.origin`;
  let checked = false;

  walkAst(handler.body, (node) => {
    if (checked) {
      return;
    }

    if (node.type === 'IfStatement' || node.type === 'ConditionalExpression') {
      const testText = normalizeText(getNodeText(node.test, sourceText));

      if (testText.includes(originText)) {
        checked = true;
      }

      return;
    }

    if (node.type !== 'SwitchStatement') {
      return;
    }

    const discriminantText = normalizeText(
      getNodeText(node.discriminant, sourceText),
    );

    if (discriminantText.includes(originText)) {
      checked = true;
    }
  });

  return checked;
}

export function collectExpressModelBindings(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  const maybeAddImport = (
    localName: string | undefined,
    sourceValue: string | undefined,
  ) => {
    if (!localName || !sourceValue) {
      return;
    }

    if (/(db|data|model|models|mongo|schema)/iu.test(sourceValue)) {
      names.add(localName);
    }
  };

  walkAst(context.program, (node) => {
    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers) {
        maybeAddImport(
          specifier.local.name,
          typeof node.source.value === 'string' ? node.source.value : undefined,
        );
      }

      return;
    }

    if (
      node.type !== 'VariableDeclarator' ||
      node.id.type !== 'Identifier' ||
      !node.init ||
      node.init.type !== 'CallExpression' ||
      node.init.callee.type !== 'Identifier' ||
      node.init.callee.name !== 'require'
    ) {
      return;
    }

    const sourceValue = getLiteralString(
      node.init.arguments[0] as TSESTree.Expression,
    );
    maybeAddImport(node.id.name, sourceValue);
  });

  return names;
}

export function collectDynamodbClientBindings(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  walkAst(context.program, (node) => {
    if (
      node.type !== 'VariableDeclarator' ||
      node.id.type !== 'Identifier' ||
      !node.init ||
      node.init.type !== 'NewExpression'
    ) {
      return;
    }

    const calleeText = getNodeText(node.init.callee, context.sourceText);

    if (calleeText === 'AWS.DynamoDB.DocumentClient') {
      names.add(node.id.name);
    }
  });

  return names;
}
