import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getNodeText,
  normalizeText,
  walkAst,
} from './custom-facts/shared';

export interface TrustBoundaryValidationState {
  expressions: Set<string>;
  identifiers: Set<string>;
}

export const trustBoundaryExternalInputRootNames = new Set([
  'ctx',
  'context',
  'event',
  'location',
  'req',
  'request',
  'window',
]);

export const trustBoundaryExternalInputPathSegments = new Set([
  'authorization',
  'body',
  'cookie',
  'cookies',
  'formdata',
  'header',
  'headers',
  'input',
  'param',
  'params',
  'payload',
  'query',
  'search',
  'searchparams',
  'session',
]);

export const trustBoundaryRequestSourcePattern =
  /(?:\b(?:req|request|ctx|context|event)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|\b(?:authorization|body|cookie|cookies|formData|header|headers|input|param|params|payload|query|search|searchParams|session)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/u;

export const trustBoundarySensitiveConstructorCallees = new Set([
  'RegExp',
  'URL',
]);

export const trustBoundaryUnsafeDeserializationCallees = new Set([
  'JSON.parse',
  'deserialize',
  'jsyaml.load',
  'qs.parse',
  'yaml.load',
  'yaml.safeLoad',
]);

export const trustBoundaryModuleLoaderCallees = new Set([
  'require',
]);

export const trustBoundaryTemplateCompilerCallees = new Set([
  'Handlebars.compile',
  'handlebars.compile',
]);

export const trustBoundaryViewRenderSinkCallees = new Set([
  'res.render',
]);

export const trustBoundaryValidationCalleePattern =
  /(^|\.)(allowlist[A-Z_]|allowlist$|assert[A-Z_]|assert$|check[A-Z_]|check$|safeParse$|sanitize[A-Z_]|sanitize$|validate[A-Z_]|validate$|verify[A-Z_]|verify$)/;

export function createTrustBoundaryValidationState(): TrustBoundaryValidationState {
  return {
    expressions: new Set<string>(),
    identifiers: new Set<string>(),
  };
}

export function leafTrustBoundaryCalleeName(
  text: string | undefined,
): string | undefined {
  if (!text) {
    return undefined;
  }

  return text
    .split('.')
    .at(-1)
    ?.replace(/\?$/u, '')
    .replace(/^#/u, '');
}

export function isValidationLikeCalleeText(
  text: string | undefined,
): boolean {
  return Boolean(text && trustBoundaryValidationCalleePattern.test(text));
}

export function isValidationLikeCall(
  node: TSESTree.CallExpression | null | undefined,
  sourceText: string,
): boolean {
  return Boolean(
    node &&
      isValidationLikeCalleeText(getNodeText(node.callee, sourceText)),
  );
}

export function isTrustBoundaryExternalInputPath(
  segments: readonly string[],
): boolean {
  if (segments.length < 2) {
    return false;
  }

  return (
    trustBoundaryExternalInputRootNames.has(segments[0]!.toLowerCase()) &&
    segments.some((segment, index) =>
      index > 0 &&
      trustBoundaryExternalInputPathSegments.has(segment.toLowerCase()),
    )
  );
}

export function collectReferencedIdentifiers(
  node: TSESTree.Node,
): Set<string> {
  const names = new Set<string>();

  walkAst(node, (candidate) => {
    if (candidate.type === 'Identifier') {
      names.add(candidate.name);
    }
  });

  return names;
}

export function noteValidatedTrustBoundaryExpression(
  state: TrustBoundaryValidationState,
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  sourceText: string,
): void {
  if (!node || node.type === 'SpreadElement') {
    return;
  }

  const expressionText = normalizeText(
    getNodeText(
      node as
        | TSESTree.Expression
        | TSESTree.PrivateIdentifier
        | null
        | undefined,
      sourceText,
    ),
  );

  if (expressionText.length > 0) {
    state.expressions.add(expressionText);
  }

  if (
    node.type === 'Identifier'
  ) {
    state.identifiers.add(node.name);
  }
}

export function isTrustBoundaryExpressionValidated(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | null
    | undefined,
  state: TrustBoundaryValidationState,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  const expressionText = normalizeText(getNodeText(node, sourceText));

  if (expressionText.length > 0 && state.expressions.has(expressionText)) {
    return true;
  }

  if (node.type === 'Identifier') {
    return state.identifiers.has(node.name);
  }

  if (node.type === 'PrivateIdentifier') {
    return false;
  }

  return [...collectReferencedIdentifiers(node)].some((name) =>
    state.identifiers.has(name),
  );
}
