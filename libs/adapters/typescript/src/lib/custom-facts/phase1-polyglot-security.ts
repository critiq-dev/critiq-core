import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  type TypeScriptFactDetector,
  walkAst,
} from './shared';

const credentialNamePattern =
  /(password|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)/i;
const requestInputPattern =
  /(req\.|request\.|query\.|params\.|body\.|process\.argv|argv\.)/;
const sqlTemplatePattern = /^`[\s\S]*\$\{[\s\S]+\}[\s\S]*`$/u;

function isStringLiteral(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): node is TSESTree.Literal {
  return node?.type === 'Literal' && typeof node.value === 'string';
}

function isExpressionNode(value: unknown): value is TSESTree.Expression {
  return Boolean(value) && typeof value === 'object' && 'type' in (value as object);
}

export const collectPhase1PolyglotSecurityFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      const identifierName =
        node.id.type === 'Identifier' ? node.id.name : undefined;

      if (
        identifierName &&
        credentialNamePattern.test(identifierName) &&
        isStringLiteral(node.init)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'security.hardcoded-credentials',
            node,
            nodeIds: context.nodeIds,
            text: getNodeText(node, context.sourceText),
          }),
        );
      }

      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const callText = getNodeText(node, context.sourceText);

    if (!calleeText || !callText) {
      return;
    }

    if (
      (calleeText === 'fs.readFile' ||
        calleeText === 'fs.readFileSync' ||
        calleeText === 'fs.promises.readFile') &&
      requestInputPattern.test(callText)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'security.request-path-file-read',
          node,
          nodeIds: context.nodeIds,
          text: callText,
          props: {
            callee: calleeText,
          },
        }),
      );
      return;
    }

    if (
      ['exec', 'execSync', 'spawn', 'spawnSync'].includes(calleeText) ||
      ['.exec', '.execSync', '.spawn', '.spawnSync'].some((suffix) =>
        calleeText.endsWith(suffix),
      )
    ) {
      if (requestInputPattern.test(callText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'security.command-execution-with-request-input',
            node,
            nodeIds: context.nodeIds,
            text: callText,
            props: {
              callee: calleeText,
            },
          }),
        );
      }

      return;
    }

    if (calleeText === 'query' || calleeText.endsWith('.query')) {
      const firstArgument = node.arguments[0];
      const firstArgumentText = isExpressionNode(firstArgument)
        ? getNodeText(firstArgument, context.sourceText)
        : undefined;

      if (firstArgumentText && sqlTemplatePattern.test(firstArgumentText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'security.sql-interpolation',
            node,
            nodeIds: context.nodeIds,
            text: callText,
            props: {
              callee: calleeText,
            },
          }),
        );
      }
    }
  });

  return facts;
};
