import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getNodeText,
  looksSensitiveIdentifier,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  isPrivilegedIdentityFieldText,
  isSensitiveAuthJwtClaimText,
} from '../../auth-vocabulary';
import { requestSourcePattern } from './constants';
import { getLiteralString, normalizeText } from './utils';
import {
  createTrustBoundaryValidationState,
  isTrustBoundaryExpressionValidated,
  isValidationLikeCall,
  noteValidatedTrustBoundaryExpression,
  type TrustBoundaryValidationState,
} from '../../trust-boundary';

export { isValidationLikeCall, type TrustBoundaryValidationState } from '../../trust-boundary';

export type FunctionLikeNode =
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression;

function looksLikeUploadSource(text: string): boolean {
  return (
    /\boriginalname\b/u.test(text) &&
    (/\bfile(?:\?\.|\.)originalname\b/u.test(text) ||
      /\b(?:req|request|ctx|context|event)(?:\?\.|\.)files?\b/u.test(text))
  );
}

function isDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  derivedNames: ReadonlySet<string>,
  sourceText: string,
  matchesSourceText: (text: string) => boolean,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return derivedNames.has(node.name);
  }

  if (node.type === 'CallExpression' && isValidationLikeCall(node, sourceText)) {
    return false;
  }

  const text = normalizeText(getNodeText(node, sourceText));

  if (text.length > 0 && matchesSourceText(text)) {
    return true;
  }

  switch (node.type) {
    case 'ArrayExpression':
      return node.elements.some((element) =>
        element
          ? isDerivedExpression(
              element,
              derivedNames,
              sourceText,
              matchesSourceText,
            )
          : false,
      );
    case 'AssignmentExpression':
    case 'BinaryExpression':
    case 'LogicalExpression':
      return (
        isDerivedExpression(
          node.left,
          derivedNames,
          sourceText,
          matchesSourceText,
        ) ||
        isDerivedExpression(
          node.right,
          derivedNames,
          sourceText,
          matchesSourceText,
        )
      );
    case 'AwaitExpression':
    case 'UnaryExpression':
      return isDerivedExpression(
        node.argument,
        derivedNames,
        sourceText,
        matchesSourceText,
      );
    case 'CallExpression':
      return node.arguments.some((argument) =>
        isDerivedExpression(
          argument,
          derivedNames,
          sourceText,
          matchesSourceText,
        ),
      );
    case 'NewExpression':
      return node.arguments.some((argument) =>
        isDerivedExpression(
          argument,
          derivedNames,
          sourceText,
          matchesSourceText,
        ),
      );
    case 'ChainExpression':
      return isDerivedExpression(
        node.expression,
        derivedNames,
        sourceText,
        matchesSourceText,
      );
    case 'ConditionalExpression':
      return (
        isDerivedExpression(
          node.test,
          derivedNames,
          sourceText,
          matchesSourceText,
        ) ||
        isDerivedExpression(
          node.consequent,
          derivedNames,
          sourceText,
          matchesSourceText,
        ) ||
        isDerivedExpression(
          node.alternate,
          derivedNames,
          sourceText,
          matchesSourceText,
        )
      );
    case 'MemberExpression':
      return matchesSourceText(text);
    case 'ObjectExpression':
      return node.properties.some((property) => {
        if (property.type === 'Property') {
          return (
            isDerivedExpression(
              property.key,
              derivedNames,
              sourceText,
              matchesSourceText,
            ) ||
            isDerivedExpression(
              property.value,
              derivedNames,
              sourceText,
              matchesSourceText,
            )
          );
        }

        return isDerivedExpression(
          property.argument,
          derivedNames,
          sourceText,
          matchesSourceText,
        );
      });
    case 'TemplateLiteral':
      return node.expressions.some((expression) =>
        isDerivedExpression(
          expression,
          derivedNames,
          sourceText,
          matchesSourceText,
        ),
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isDerivedExpression(
        node.expression,
        derivedNames,
        sourceText,
        matchesSourceText,
      );
    default:
      return false;
  }
}

export function isRequestDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  return isDerivedExpression(node, taintedNames, sourceText, (text) =>
    requestSourcePattern.test(text),
  );
}

export function isUploadDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  return isDerivedExpression(node, taintedNames, sourceText, looksLikeUploadSource);
}

function collectDerivedNames(
  context: TypeScriptFactDetectorContext,
  isDerived: (
    node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
    derivedNames: ReadonlySet<string>,
    sourceText: string,
  ) => boolean,
): Set<string> {
  const derivedNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (isDerived(node.init, derivedNames, context.sourceText)) {
        derivedNames.add(node.id.name);
      }

      return;
    }

    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'Identifier'
    ) {
      return;
    }

    if (isDerived(node.right, derivedNames, context.sourceText)) {
      derivedNames.add(node.left.name);
    }
  });

  return derivedNames;
}

export function collectRequestDerivedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  return collectDerivedNames(context, isRequestDerivedExpression);
}

export function collectUploadDerivedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  return collectDerivedNames(context, isUploadDerivedExpression);
}

export function collectValidatedTrustBoundaryState(
  context: TypeScriptFactDetectorContext,
): TrustBoundaryValidationState {
  const state = createTrustBoundaryValidationState();

  walkAst(context.program, (node) => {
    if (
      node.type !== 'CallExpression' ||
      !isValidationLikeCall(node, context.sourceText)
    ) {
      return;
    }

    node.arguments.forEach((argument) =>
      noteValidatedTrustBoundaryExpression(
        state,
        argument,
        context.sourceText,
      ),
    );
  });

  return state;
}

export function isValidatedTrustBoundaryExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  state: TrustBoundaryValidationState,
  sourceText: string,
): boolean {
  return isTrustBoundaryExpressionValidated(node, state, sourceText);
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
      if (isSensitiveAuthJwtClaimText(candidate.value)) {
        signals.add(candidate.value);
      }
      return;
    }

    if (candidate.type === 'MemberExpression') {
      const text = getNodeText(candidate, sourceText);

      if (looksSensitiveIdentifier(text) || isPrivilegedIdentityFieldText(text)) {
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
