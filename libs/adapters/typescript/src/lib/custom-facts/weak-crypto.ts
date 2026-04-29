import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { isAuthLikeText } from '../auth-vocabulary';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  getStringLiteralValue,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

export const WEAK_HASH_RULE_ID = 'security.weak-hash-algorithm';
export const WEAK_CIPHER_RULE_ID = 'ts.security.weak-cipher-or-mode';
export const PREDICTABLE_TOKEN_RULE_ID =
  'ts.security.predictable-token-generation';
const WEAK_HASH_FACT_KIND = 'security.weak-hash-algorithm';
const WEAK_CIPHER_FACT_KIND = 'security.weak-cipher-or-mode';
const PREDICTABLE_TOKEN_FACT_KIND = 'security.predictable-token-generation';

const weakHashAlgorithmPattern =
  /^(md4|md5|ripemd160|sha1|sha-1)$/i;

const weakHashCallNames = new Set([
  'createHash',
  'createHmac',
  'crypto.createHash',
  'crypto.createHmac',
  'crypto.subtle.digest',
  'subtle.digest',
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

const weakCipherAlgorithmPattern =
  /(?:^|[^a-z0-9])(des|3des|ecb|rc2|rc4)(?:$|[^a-z0-9])/i;

const predictableTokenTargetPattern =
  /(auth|credential|invite|magic|nonce|otp|reset|session|token|verification|verify)/i;

const predictableTokenSourcePattern =
  /(Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now)/i;

const safeRandomSourcePattern =
  /(crypto\.randomBytes|crypto\.randomUUID|globalThis\.crypto\.randomUUID|getRandomValues|randomBytes|randomUUID)/i;
const predictableSourceMatcher =
  /Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now/gi;

function normalizeAlgorithm(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
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

  return weakCipherAlgorithmPattern.test(value.toLowerCase());
}

function isTokenLikeTarget(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  return predictableTokenTargetPattern.test(text) || isAuthLikeText(text);
}

function collectPredictableSources(text: string): string[] {
  return [...new Set(text.match(predictableSourceMatcher) ?? [])];
}

function firstExpressionArgument(
  node: TSESTree.CallExpression,
): TSESTree.Expression | undefined {
  const [firstArgument] = node.arguments;

  return firstArgument && firstArgument.type !== 'SpreadElement'
    ? firstArgument
    : undefined;
}

function getLiteralString(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  return getStringLiteralValue(node);
}

function collectWeakHashFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !weakHashCallNames.has(calleeText)) {
      return;
    }

    const algorithm = getLiteralString(firstExpressionArgument(node));

    if (!isWeakHashAlgorithm(algorithm)) {
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
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !weakCipherCallNames.has(calleeText)) {
      return;
    }

    const algorithm = getLiteralString(firstExpressionArgument(node));

    if (!isWeakCipherAlgorithm(algorithm)) {
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
  });

  return facts;
}

function collectPredictableTokenFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
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
    const valueText = getNodeText(valueNode, context.sourceText);

    if (!isTokenLikeTarget(targetText)) {
      return;
    }

    if (!valueText || safeRandomSourcePattern.test(valueText)) {
      return;
    }

    if (!predictableTokenSourcePattern.test(valueText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: PREDICTABLE_TOKEN_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          target: targetText,
          predictableSources: collectPredictableSources(valueText),
        },
        text: valueText,
      }),
    );
  });

  return facts;
}

function isFunctionLike(
  node: TSESTree.Node | null | undefined,
): node is
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression {
  return Boolean(
    node &&
      (node.type === 'ArrowFunctionExpression' ||
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression'),
  );
}

function walkFunctionBodySkippingNestedFunctions(
  root:
    | TSESTree.ArrowFunctionExpression
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression,
  visitor: (node: TSESTree.Node) => void,
): void {
  const visit = (node: TSESTree.Node): void => {
    if (isFunctionLike(node) && node !== root) {
      return;
    }

    visitor(node);

    for (const value of Object.values(node)) {
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

  if (root.body.type === 'BlockStatement') {
    for (const statement of root.body.body) {
      visit(statement);
    }

    return;
  }

  visit(root.body);
}

function collectPredictableTokenReturnFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  const collectFactsForFunction = (
    functionNode:
      | TSESTree.ArrowFunctionExpression
      | TSESTree.FunctionDeclaration
      | TSESTree.FunctionExpression,
    target: string,
  ): void => {
    const returnExpressions: TSESTree.Expression[] = [];

    walkFunctionBodySkippingNestedFunctions(functionNode, (node) => {
      if (node.type !== 'ReturnStatement' || !node.argument) {
        return;
      }

      returnExpressions.push(node.argument);
    });

    if (
      functionNode.body.type !== 'BlockStatement' &&
      !returnExpressions.includes(functionNode.body)
    ) {
      returnExpressions.push(functionNode.body);
    }

    for (const expression of returnExpressions) {
      const valueText = getNodeText(expression, context.sourceText);

      if (!valueText || safeRandomSourcePattern.test(valueText)) {
        continue;
      }

      if (!predictableTokenSourcePattern.test(valueText)) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: PREDICTABLE_TOKEN_FACT_KIND,
          node: expression,
          nodeIds: context.nodeIds,
          props: {
            target,
            predictableSources: collectPredictableSources(valueText),
          },
          text: valueText,
        }),
      );
    }
  };

  walkAst(context.program, (node) => {
    if (
      node.type === 'FunctionDeclaration' &&
      node.id &&
      isTokenLikeTarget(node.id.name)
    ) {
      collectFactsForFunction(node, node.id.name);
      return;
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      isTokenLikeTarget(node.id.name) &&
      isFunctionLike(node.init)
    ) {
      collectFactsForFunction(node.init, node.id.name);
    }
  });

  return facts;
}

export const collectWeakCryptoFacts: TypeScriptFactDetector = (context) => {
  const facts = [
    ...collectWeakHashFacts(context),
    ...collectWeakCipherFacts(context),
    ...collectPredictableTokenFacts(context),
    ...collectPredictableTokenReturnFacts(context),
  ];

  const uniqueFacts = new Map<string, ObservedFact>();

  for (const fact of facts) {
    uniqueFacts.set(fact.id, fact);
  }

  return [...uniqueFacts.values()];
};
