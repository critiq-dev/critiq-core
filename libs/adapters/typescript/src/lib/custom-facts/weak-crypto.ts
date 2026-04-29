import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isAuthLikeText,
  tokenizeIdentifierLikeText,
} from '../auth-vocabulary';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getNumericLiteralValue,
  getObjectProperty,
  getStringLiteralValue,
  hasCompatibilityMarkerNearNode,
  isCompatibilityMarkerText,
  isFunctionLike,
  normalizeText,
  walkAst,
  walkAstWithAncestors,
  walkFunctionBodySkippingNestedFunctions,
  type FunctionLikeNode,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const WEAK_HASH_RULE_ID = 'security.weak-hash-algorithm';
export const WEAK_CIPHER_RULE_ID = 'ts.security.weak-cipher-or-mode';
export const PREDICTABLE_TOKEN_RULE_ID =
  'ts.security.predictable-token-generation';
export const INSECURE_PASSWORD_HASH_CONFIG_RULE_ID =
  'ts.security.insecure-password-hash-configuration';
export const INSUFFICIENT_RANDOM_RULE_ID =
  'ts.security.insufficiently-random-values';
export const WEAK_KEY_STRENGTH_RULE_ID = 'ts.security.weak-key-strength';
export const MISSING_INTEGRITY_RULE_ID =
  'ts.security.missing-integrity-check';

const WEAK_HASH_FACT_KIND = 'security.weak-hash-algorithm';
const WEAK_CIPHER_FACT_KIND = 'security.weak-cipher-or-mode';
const PREDICTABLE_TOKEN_FACT_KIND = 'security.predictable-token-generation';
const INSECURE_PASSWORD_HASH_CONFIG_FACT_KIND =
  'security.insecure-password-hash-configuration';
const INSUFFICIENT_RANDOM_FACT_KIND = 'security.insufficiently-random-values';
const WEAK_KEY_STRENGTH_FACT_KIND = 'security.weak-key-strength';
const MISSING_INTEGRITY_FACT_KIND = 'security.missing-integrity-check';

const weakHashAlgorithmPattern = /^(md4|md5|ripemd160|sha1)$/i;
const sensitivePasswordValuePattern =
  /(?:password|passphrase|hash|secret|token|api[_-]?key|auth[_-]?token)/i;
const predictableTokenSourcePattern =
  /(Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now)/i;
const predictableSourceMatcher =
  /Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now/gi;

const compatibilitySensitiveTargetTokens = new Set([
  'api',
  'auth',
  'client',
  'cookie',
  'credential',
  'invite',
  'jwt',
  'magic',
  'nonce',
  'otp',
  'passcode',
  'refresh',
  'reset',
  'secret',
  'session',
  'signing',
  'token',
  'verification',
  'verify',
]);

const otpLikeTargetTokens = new Set([
  '2fa',
  'code',
  'one',
  'otp',
  'passcode',
  'pin',
  'time',
  'totp',
  'verification',
]);

const weakHashCallNames = new Set([
  'createHash',
  'createHmac',
  'crypto.createHash',
  'crypto.createHmac',
  'crypto.subtle.digest',
  'globalThis.crypto.subtle.digest',
  'subtle.digest',
]);

const pbkdf2CallNames = new Set([
  'pbkdf2',
  'pbkdf2Sync',
  'crypto.pbkdf2',
  'crypto.pbkdf2Sync',
]);

const weakCipherCallNames = new Set([
  'createCipher',
  'createCipheriv',
  'createDecipher',
  'createDecipheriv',
  'crypto.createCipher',
  'crypto.createCipheriv',
  'crypto.createDecipher',
  'crypto.createDecipheriv',
]);

const rsaPaddingCallNames = new Set([
  'privateDecrypt',
  'privateEncrypt',
  'publicDecrypt',
  'publicEncrypt',
  'crypto.privateDecrypt',
  'crypto.privateEncrypt',
  'crypto.publicDecrypt',
  'crypto.publicEncrypt',
]);

const rsaKeyGenerationCallNames = new Set([
  'generateKeyPair',
  'generateKeyPairSync',
  'crypto.generateKeyPair',
  'crypto.generateKeyPairSync',
]);

const symmetricKeyGenerationCallNames = new Set([
  'generateKey',
  'generateKeySync',
  'crypto.generateKey',
  'crypto.generateKeySync',
]);

const webCryptoGenerateKeyCallNames = new Set([
  'crypto.subtle.generateKey',
  'globalThis.crypto.subtle.generateKey',
  'subtle.generateKey',
]);

const integrityHelperCallNames = new Set([
  'createHmac',
  'crypto.createHmac',
  'crypto.subtle.sign',
  'globalThis.crypto.subtle.sign',
  'subtle.sign',
]);

type ExpressionBindingMap = Map<string, TSESTree.Expression>;

interface SecretValueCandidate {
  ancestors: readonly TSESTree.Node[];
  suppressionNode: TSESTree.Node;
  target: string;
  valueNode: TSESTree.Expression;
}

interface SecureRandomEntropyInfo {
  entropyBytes: number;
  source: string;
}

interface IntegrityIssue {
  algorithm: string;
  ivIssue?: 'fixed' | 'predictable';
  sink: string;
}

function normalizeAlgorithm(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function toExpression(
  argument: TSESTree.CallExpressionArgument | undefined,
): TSESTree.Expression | undefined {
  return argument && argument.type !== 'SpreadElement' ? argument : undefined;
}

function unwrapExpression(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
): TSESTree.Expression | TSESTree.PrivateIdentifier | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'TSAsExpression' || node.type === 'TSTypeAssertion') {
    return unwrapExpression(node.expression);
  }

  if (node.type === 'ChainExpression') {
    return unwrapExpression(node.expression);
  }

  if (node.type === 'SpreadElement') {
    return undefined;
  }

  return node;
}

function collectExpressionBindings(
  context: TypeScriptFactDetectorContext,
): ExpressionBindingMap {
  const bindings = new Map<string, TSESTree.Expression>();

  walkAst(context.program, (node) => {
    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      node.init
    ) {
      bindings.set(node.id.name, node.init);
      return;
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'Identifier'
    ) {
      bindings.set(node.left.name, node.right);
    }
  });

  return bindings;
}

function resolveExpression(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  bindings: ExpressionBindingMap,
  visited = new Set<string>(),
): TSESTree.Expression | TSESTree.PrivateIdentifier | undefined {
  const unwrapped = unwrapExpression(node);

  if (!unwrapped) {
    return undefined;
  }

  if (unwrapped.type !== 'Identifier') {
    return unwrapped;
  }

  if (visited.has(unwrapped.name)) {
    return unwrapped;
  }

  const binding = bindings.get(unwrapped.name);

  if (!binding) {
    return unwrapped;
  }

  visited.add(unwrapped.name);

  return resolveExpression(binding, bindings, visited) ?? binding;
}

function getLiteralStringValue(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): string | undefined {
  const resolved = resolveExpression(node, bindings);

  if (!resolved || resolved.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (resolved.type === 'TemplateLiteral' && resolved.expressions.length === 0) {
    return resolved.quasis.map((quasi) => quasi.value.cooked ?? '').join('');
  }

  return getStringLiteralValue(resolved);
}

function getLiteralNumberValue(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  bindings: ExpressionBindingMap,
): number | undefined {
  return getNumericLiteralValue(resolveExpression(node, bindings));
}

function resolveObjectExpression(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  bindings: ExpressionBindingMap,
): TSESTree.ObjectExpression | undefined {
  const resolved = resolveExpression(node, bindings);

  return resolved?.type === 'ObjectExpression' ? resolved : undefined;
}

function getObjectStringProperty(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): string | undefined {
  return getLiteralStringValue(
    getObjectProperty(objectExpression, name)?.value as
      | TSESTree.Expression
      | TSESTree.PrivateIdentifier
      | undefined,
    context,
    bindings,
  );
}

function getObjectNumberProperty(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
  bindings: ExpressionBindingMap,
): number | undefined {
  return getLiteralNumberValue(
    getObjectProperty(objectExpression, name)?.value as
      | TSESTree.Expression
      | TSESTree.PrivateIdentifier
      | undefined,
    bindings,
  );
}

function getObjectPropertyText(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): string | undefined {
  const property = getObjectProperty(objectExpression, name);

  if (!property) {
    return undefined;
  }

  return (
    getLiteralStringValue(
      property.value as TSESTree.Expression | TSESTree.PrivateIdentifier,
      context,
      bindings,
    ) ??
    getNodeText(
      resolveExpression(
        property.value as TSESTree.Expression | TSESTree.PrivateIdentifier,
        bindings,
      ) ??
        property.value,
      context.sourceText,
    )
  );
}

function extractAlgorithmName(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): string | undefined {
  const directValue = getLiteralStringValue(node, context, bindings);

  if (directValue) {
    return directValue;
  }

  const objectExpression = resolveObjectExpression(node, bindings);

  if (!objectExpression) {
    return undefined;
  }

  return getObjectStringProperty(objectExpression, 'name', context, bindings);
}

function isPredictableSourceText(text: string | undefined): boolean {
  return Boolean(text && predictableTokenSourcePattern.test(text));
}

function isWeakHashAlgorithm(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  return weakHashAlgorithmPattern.test(normalizeAlgorithm(value));
}

function isWeakCipherAlgorithm(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  const normalized = normalizeAlgorithm(value);

  return (
    normalized.includes('ecb') ||
    normalized === 'des' ||
    normalized.startsWith('des') ||
    normalized.includes('3des') ||
    normalized.includes('desede3') ||
    normalized.includes('tripledes') ||
    normalized.includes('rc2') ||
    normalized.includes('rc4') ||
    normalized.includes('blowfish') ||
    normalized.startsWith('bf')
  );
}

function isNonAeadCipherAlgorithm(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  const normalized = normalizeAlgorithm(value);

  return normalized.includes('cbc');
}

function isRsaKeyAlgorithm(value: string | undefined): boolean {
  return Boolean(value && normalizeAlgorithm(value).includes('rsa'));
}

function isSymmetricKeyLengthAlgorithm(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  const normalized = normalizeAlgorithm(value);

  return normalized.startsWith('aes') || normalized === 'hmac';
}

function isSecretLikeTarget(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  if (isAuthLikeText(text)) {
    return true;
  }

  return tokenizeIdentifierLikeText(text).some((token) =>
    compatibilitySensitiveTargetTokens.has(token),
  );
}

function isOtpLikeTarget(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  const tokens = tokenizeIdentifierLikeText(text);

  return (
    tokens.includes('otp') ||
    tokens.includes('totp') ||
    tokens.includes('pin') ||
    tokens.includes('passcode') ||
    (tokens.includes('verification') && tokens.includes('code')) ||
    (tokens.includes('one') && tokens.includes('time')) ||
    tokens.some((token) => otpLikeTargetTokens.has(token))
  );
}

function collectPredictableSources(text: string): string[] {
  return [...new Set(text.match(predictableSourceMatcher) ?? [])];
}

function isCompatibilitySuppressed(options: {
  ancestors?: readonly TSESTree.Node[];
  context: TypeScriptFactDetectorContext;
  node: TSESTree.Node;
  target?: string;
}): boolean {
  return (
    isCompatibilityMarkerText(options.target) ||
    hasCompatibilityMarkerNearNode({
      ancestors: options.ancestors,
      node: options.node,
      program: options.context.program,
      sourceText: options.context.sourceText,
    })
  );
}

function collectSecretValueCandidates(
  context: TypeScriptFactDetectorContext,
): SecretValueCandidate[] {
  const candidates: SecretValueCandidate[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (
      node.type !== 'VariableDeclarator' &&
      node.type !== 'AssignmentExpression'
    ) {
      return;
    }

    const targetNode =
      node.type === 'VariableDeclarator' ? node.id : node.left;
    const valueNode =
      node.type === 'VariableDeclarator' ? node.init : node.right;

    if (!valueNode) {
      return;
    }

    const targetText = getNodeText(targetNode, context.sourceText);

    if (!isSecretLikeTarget(targetText)) {
      return;
    }

    candidates.push({
      ancestors,
      suppressionNode: node,
      target: targetText ?? '',
      valueNode,
    });
  });

  const collectReturnCandidates = (
    functionNode: FunctionLikeNode,
    ancestors: readonly TSESTree.Node[],
    target: string,
  ): void => {
    const returnExpressions: TSESTree.Expression[] = [];

    walkFunctionBodySkippingNestedFunctions(functionNode, (node) => {
      if (node.type === 'ReturnStatement' && node.argument) {
        returnExpressions.push(node.argument);
      }
    });

    if (
      functionNode.body.type !== 'BlockStatement' &&
      !returnExpressions.includes(functionNode.body)
    ) {
      returnExpressions.push(functionNode.body);
    }

    for (const expression of returnExpressions) {
      candidates.push({
        ancestors,
        suppressionNode: functionNode,
        target,
        valueNode: expression,
      });
    }
  };

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (
      node.type === 'FunctionDeclaration' &&
      node.id &&
      isSecretLikeTarget(node.id.name)
    ) {
      collectReturnCandidates(node, ancestors, node.id.name);
      return;
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      isSecretLikeTarget(node.id.name) &&
      isFunctionLike(node.init)
    ) {
      collectReturnCandidates(node.init, ancestors, node.id.name);
    }
  });

  return candidates;
}

function getResolvedValueText(
  node: TSESTree.Expression,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): string | undefined {
  return getNodeText(resolveExpression(node, bindings) ?? node, context.sourceText);
}

function getPropertyName(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  return getNodeText(node, sourceText);
}

function getSecureRandomEntropyInfo(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): SecureRandomEntropyInfo | undefined {
  const resolved = resolveExpression(node, bindings);

  if (!resolved || resolved.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (resolved.type === 'CallExpression') {
    if (resolved.callee.type === 'MemberExpression') {
      const propertyName = getPropertyName(
        resolved.callee.property,
        context.sourceText,
      );

      if (propertyName === 'toString' || propertyName === 'valueOf') {
        return getSecureRandomEntropyInfo(
          resolved.callee.object,
          context,
          bindings,
        );
      }
    }

    const calleeText = getCalleeText(resolved.callee, context.sourceText);

    if (calleeText === 'Buffer.from') {
      return getSecureRandomEntropyInfo(
        toExpression(resolved.arguments[0]),
        context,
        bindings,
      );
    }

    if (calleeText === 'randomUUID' || calleeText === 'crypto.randomUUID') {
      return {
        entropyBytes: 16,
        source: calleeText,
      };
    }

    if (calleeText === 'randomBytes' || calleeText === 'crypto.randomBytes') {
      const entropyBytes = getLiteralNumberValue(
        toExpression(resolved.arguments[0]),
        bindings,
      );

      if (entropyBytes === undefined) {
        return undefined;
      }

      return {
        entropyBytes,
        source: calleeText,
      };
    }

    if (
      calleeText === 'getRandomValues' ||
      calleeText === 'crypto.getRandomValues' ||
      calleeText === 'globalThis.crypto.getRandomValues' ||
      calleeText === 'crypto.webcrypto.getRandomValues'
    ) {
      const target = resolveExpression(toExpression(resolved.arguments[0]), bindings);

      if (!target) {
        return undefined;
      }

      if (target.type === 'NewExpression') {
        const arrayType = getNodeText(target.callee, context.sourceText);
        const elementCount = getLiteralNumberValue(
          toExpression(target.arguments[0]),
          bindings,
        );

        if (elementCount === undefined) {
          return undefined;
        }

        const bytesPerElement =
          arrayType === 'Uint32Array'
            ? 4
            : arrayType === 'Uint16Array'
              ? 2
              : arrayType === 'Uint8Array'
                ? 1
                : undefined;

        if (!bytesPerElement) {
          return undefined;
        }

        return {
          entropyBytes: elementCount * bytesPerElement,
          source: calleeText,
        };
      }
    }
  }

  return undefined;
}

function getNearestFunctionLikeAncestor(
  ancestors: readonly TSESTree.Node[],
): FunctionLikeNode | undefined {
  return [...ancestors]
    .reverse()
    .find((ancestor): ancestor is FunctionLikeNode => isFunctionLike(ancestor));
}

function hasSameFunctionIntegrityHelper(
  functionNode: FunctionLikeNode | undefined,
  context: TypeScriptFactDetectorContext,
): boolean {
  if (!functionNode) {
    return false;
  }

  let foundHelper = false;

  walkFunctionBodySkippingNestedFunctions(functionNode, (node) => {
    if (foundHelper || node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText && integrityHelperCallNames.has(calleeText)) {
      foundHelper = true;
    }
  });

  return foundHelper;
}

function classifyIvIssue(
  node:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.CallExpressionArgument
    | null
    | undefined,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): 'fixed' | 'predictable' | undefined {
  const resolved = resolveExpression(node, bindings);
  const text = getNodeText(resolved ?? node ?? null, context.sourceText);

  if (!resolved || !text) {
    return undefined;
  }

  if (isPredictableSourceText(text)) {
    return 'predictable';
  }

  if (
    resolved.type === 'Literal' ||
    resolved.type === 'ArrayExpression' ||
    resolved.type === 'TemplateLiteral'
  ) {
    return 'fixed';
  }

  if (resolved.type === 'NewExpression') {
    return 'fixed';
  }

  if (resolved.type !== 'CallExpression') {
    return undefined;
  }

  const calleeText = getCalleeText(resolved.callee, context.sourceText);

  if (calleeText === 'Buffer.alloc') {
    return 'fixed';
  }

  if (calleeText === 'Buffer.from') {
    const firstArgument = toExpression(resolved.arguments[0]);
    const firstArgumentText = getNodeText(
      resolveExpression(firstArgument, bindings) ?? firstArgument ?? null,
      context.sourceText,
    );

    if (!firstArgumentText) {
      return undefined;
    }

    return isPredictableSourceText(firstArgumentText) ? 'predictable' : 'fixed';
  }

  return undefined;
}

function findIntegrityIssueInExpression(
  node: TSESTree.Expression,
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): IntegrityIssue | undefined {
  let issue: IntegrityIssue | undefined;
  const resolvedNode = resolveExpression(node, bindings);

  if (!resolvedNode || resolvedNode.type === 'PrivateIdentifier') {
    return undefined;
  }

  walkAst(resolvedNode, (candidate) => {
    if (issue || candidate.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(candidate.callee, context.sourceText);

    if (!calleeText || !weakCipherCallNames.has(calleeText)) {
      return;
    }

    const algorithm = extractAlgorithmName(
      toExpression(candidate.arguments[0]),
      context,
      bindings,
    );

    if (
      !algorithm ||
      isWeakCipherAlgorithm(algorithm) ||
      !isNonAeadCipherAlgorithm(algorithm)
    ) {
      return;
    }

    issue = {
      algorithm,
      ivIssue: classifyIvIssue(
        toExpression(candidate.arguments[2]),
        context,
        bindings,
      ),
      sink: calleeText,
    };
  });

  return issue;
}

function collectWeakHashFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText) {
      return;
    }

    let algorithm: string | undefined;

    if (weakHashCallNames.has(calleeText)) {
      algorithm = extractAlgorithmName(
        toExpression(node.arguments[0]),
        context,
        bindings,
      );
    } else if (pbkdf2CallNames.has(calleeText)) {
      algorithm = getLiteralStringValue(
        toExpression(node.arguments[4]),
        context,
        bindings,
      );
    } else {
      return;
    }

    if (
      !isWeakHashAlgorithm(algorithm) ||
      isCompatibilitySuppressed({
        ancestors,
        context,
        node,
      })
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: WEAK_HASH_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          algorithm,
          sink: calleeText,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectWeakCipherFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText) {
      return;
    }

    if (weakCipherCallNames.has(calleeText)) {
      const algorithm = extractAlgorithmName(
        toExpression(node.arguments[0]),
        context,
        bindings,
      );

      if (
        !isWeakCipherAlgorithm(algorithm) ||
        isCompatibilitySuppressed({
          ancestors,
          context,
          node,
        })
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: WEAK_CIPHER_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          props: {
            algorithm,
            sink: calleeText,
          },
          text: getNodeText(node, context.sourceText),
        }),
      );

      return;
    }

    if (!rsaPaddingCallNames.has(calleeText)) {
      return;
    }

    const options = resolveObjectExpression(
      toExpression(node.arguments[0]),
      bindings,
    );
    const paddingText = getObjectPropertyText(
      options,
      'padding',
      context,
      bindings,
    );

    if (
      !paddingText ||
      !normalizeText(paddingText).includes('RSA_NO_PADDING') ||
      isCompatibilitySuppressed({
        ancestors,
        context,
        node,
      })
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: WEAK_CIPHER_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          algorithm: 'RSA_NO_PADDING',
          sink: calleeText,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectInsecurePasswordHashFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'argon2.hash') {
      return;
    }

    const passwordArgument = toExpression(node.arguments[0]);
    const passwordText = getResolvedValueText(
      passwordArgument ?? node,
      context,
      bindings,
    );

    if (!passwordText || !sensitivePasswordValuePattern.test(passwordText)) {
      return;
    }

    const options = resolveObjectExpression(
      toExpression(node.arguments[1]),
      bindings,
    );
    const algorithmText = getObjectPropertyText(
      options,
      'type',
      context,
      bindings,
    );
    const normalizedAlgorithm = normalizeAlgorithm(algorithmText ?? '');

    if (
      (normalizedAlgorithm !== 'argon2i' &&
        normalizedAlgorithm !== 'argon2d' &&
        normalizedAlgorithm !== 'argon2argon2i' &&
        normalizedAlgorithm !== 'argon2argon2d') ||
      isCompatibilitySuppressed({
        ancestors,
        context,
        node,
      })
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: INSECURE_PASSWORD_HASH_CONFIG_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          algorithm: algorithmText,
        },
        text: 'argon2.hash',
      }),
    );
  });

  return facts;
}

function collectPredictableTokenFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  for (const candidate of collectSecretValueCandidates(context)) {
    const valueText = getResolvedValueText(candidate.valueNode, context, bindings);

    if (
      !valueText ||
      !isPredictableSourceText(valueText) ||
      isCompatibilitySuppressed({
        ancestors: candidate.ancestors,
        context,
        node: candidate.suppressionNode,
        target: candidate.target,
      })
    ) {
      continue;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: PREDICTABLE_TOKEN_FACT_KIND,
        node: candidate.valueNode,
        nodeIds: context.nodeIds,
        props: {
          predictableSources: collectPredictableSources(valueText),
          target: candidate.target,
        },
        text: valueText,
      }),
    );
  }

  return facts;
}

function collectInsufficientRandomFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  for (const candidate of collectSecretValueCandidates(context)) {
    if (isOtpLikeTarget(candidate.target)) {
      continue;
    }

    const entropyInfo = getSecureRandomEntropyInfo(
      candidate.valueNode,
      context,
      bindings,
    );

    if (
      !entropyInfo ||
      entropyInfo.entropyBytes >= 16 ||
      isCompatibilitySuppressed({
        ancestors: candidate.ancestors,
        context,
        node: candidate.suppressionNode,
        target: candidate.target,
      })
    ) {
      continue;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: INSUFFICIENT_RANDOM_FACT_KIND,
        node: candidate.valueNode,
        nodeIds: context.nodeIds,
        props: {
          entropyBytes: entropyInfo.entropyBytes,
          source: entropyInfo.source,
          target: candidate.target,
        },
        text: getResolvedValueText(candidate.valueNode, context, bindings),
      }),
    );
  }

  return facts;
}

function collectWeakKeyStrengthFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText) {
      return;
    }

    if (rsaKeyGenerationCallNames.has(calleeText)) {
      const algorithm = getLiteralStringValue(
        toExpression(node.arguments[0]),
        context,
        bindings,
      );
      const options = resolveObjectExpression(
        toExpression(node.arguments[1]),
        bindings,
      );
      const modulusLength = getObjectNumberProperty(
        options,
        'modulusLength',
        bindings,
      );

      if (
        !isRsaKeyAlgorithm(algorithm) ||
        modulusLength === undefined ||
        modulusLength >= 2048 ||
        isCompatibilitySuppressed({
          ancestors,
          context,
          node,
        })
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: WEAK_KEY_STRENGTH_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          props: {
            algorithm,
            declaredStrength: modulusLength,
            requiredStrength: 2048,
            sink: calleeText,
            strengthType: 'modulusLength',
          },
          text: getNodeText(node, context.sourceText),
        }),
      );

      return;
    }

    if (symmetricKeyGenerationCallNames.has(calleeText)) {
      const algorithm = getLiteralStringValue(
        toExpression(node.arguments[0]),
        context,
        bindings,
      );
      const options = resolveObjectExpression(
        toExpression(node.arguments[1]),
        bindings,
      );
      const length = getObjectNumberProperty(options, 'length', bindings);

      if (
        !isSymmetricKeyLengthAlgorithm(algorithm) ||
        length === undefined ||
        length >= 128 ||
        isCompatibilitySuppressed({
          ancestors,
          context,
          node,
        })
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: WEAK_KEY_STRENGTH_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          props: {
            algorithm,
            declaredStrength: length,
            requiredStrength: 128,
            sink: calleeText,
            strengthType: 'keyLength',
          },
          text: getNodeText(node, context.sourceText),
        }),
      );

      return;
    }

    if (!webCryptoGenerateKeyCallNames.has(calleeText)) {
      return;
    }

    const algorithmObject = resolveObjectExpression(
      toExpression(node.arguments[0]),
      bindings,
    );
    const algorithmName = extractAlgorithmName(
      toExpression(node.arguments[0]),
      context,
      bindings,
    );

    if (
      !algorithmObject ||
      isCompatibilitySuppressed({
        ancestors,
        context,
        node,
      })
    ) {
      return;
    }

    const modulusLength = getObjectNumberProperty(
      algorithmObject,
      'modulusLength',
      bindings,
    );

    if (
      isRsaKeyAlgorithm(algorithmName) &&
      modulusLength !== undefined &&
      modulusLength < 2048
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: WEAK_KEY_STRENGTH_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          props: {
            algorithm: algorithmName,
            declaredStrength: modulusLength,
            requiredStrength: 2048,
            sink: calleeText,
            strengthType: 'modulusLength',
          },
          text: getNodeText(node, context.sourceText),
        }),
      );

      return;
    }

    const keyLength = getObjectNumberProperty(algorithmObject, 'length', bindings);

    if (
      isSymmetricKeyLengthAlgorithm(algorithmName) &&
      keyLength !== undefined &&
      keyLength < 128
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: WEAK_KEY_STRENGTH_FACT_KIND,
          node,
          nodeIds: context.nodeIds,
          props: {
            algorithm: algorithmName,
            declaredStrength: keyLength,
            requiredStrength: 128,
            sink: calleeText,
            strengthType: 'keyLength',
          },
          text: getNodeText(node, context.sourceText),
        }),
      );
    }
  });

  return facts;
}

function collectMissingIntegrityFacts(
  context: TypeScriptFactDetectorContext,
  bindings: ExpressionBindingMap,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  for (const candidate of collectSecretValueCandidates(context)) {
    const integrityIssue = findIntegrityIssueInExpression(
      candidate.valueNode,
      context,
      bindings,
    );
    const functionNode = isFunctionLike(candidate.suppressionNode)
      ? candidate.suppressionNode
      : getNearestFunctionLikeAncestor(candidate.ancestors);

    if (
      !integrityIssue ||
      hasSameFunctionIntegrityHelper(functionNode, context) ||
      isCompatibilitySuppressed({
        ancestors: candidate.ancestors,
        context,
        node: candidate.suppressionNode,
        target: candidate.target,
      })
    ) {
      continue;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: MISSING_INTEGRITY_FACT_KIND,
        node: candidate.valueNode,
        nodeIds: context.nodeIds,
        props: {
          algorithm: integrityIssue.algorithm,
          ivIssue: integrityIssue.ivIssue,
          sink: integrityIssue.sink,
          target: candidate.target,
        },
        text: getResolvedValueText(candidate.valueNode, context, bindings),
      }),
    );
  }

  return facts;
}

export const collectWeakCryptoFacts: TypeScriptFactDetector = (context) => {
  const bindings = collectExpressionBindings(context);
  const facts = [
    ...collectWeakHashFacts(context, bindings),
    ...collectWeakCipherFacts(context, bindings),
    ...collectInsecurePasswordHashFacts(context, bindings),
    ...collectPredictableTokenFacts(context, bindings),
    ...collectInsufficientRandomFacts(context, bindings),
    ...collectWeakKeyStrengthFacts(context, bindings),
    ...collectMissingIntegrityFacts(context, bindings),
  ];

  const uniqueFacts = new Map<string, ObservedFact>();

  for (const fact of facts) {
    uniqueFacts.set(fact.id, fact);
  }

  return [...uniqueFacts.values()];
};
