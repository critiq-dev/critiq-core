import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const SYNC_COMMAND_SINKS = new Set(['execSync', 'spawnSync']);

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

function isStaticCommandArgument(
  node: TSESTree.Expression | TSESTree.SpreadElement | undefined,
): boolean {
  if (!node || node.type === 'SpreadElement') {
    return false;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return true;
  }

  if (
    node.type === 'TemplateLiteral' &&
    node.expressions.length === 0 &&
    node.quasis.length === 1
  ) {
    return true;
  }

  return false;
}

/** `execSync` / `spawnSync` calls whose command argument is not a fixed string. */
export function collectSyncChildProcessExecFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const calleeLeaf = leafCalleeName(calleeText);

    if (!calleeLeaf || !SYNC_COMMAND_SINKS.has(calleeLeaf)) {
      return;
    }

    const commandArgument = node.arguments[0];

    if (isStaticCommandArgument(commandArgument)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'security.sync-child-process-exec',
        node,
        nodeIds: context.nodeIds,
        text: getNodeText(node, context.sourceText) ?? calleeLeaf,
        props: {
          callee: calleeText ?? calleeLeaf,
        },
      }),
    );
  });

  return facts;
}

export const collectSyncChildProcessExecFactsDetector: TypeScriptFactDetector = (
  context,
) => collectSyncChildProcessExecFacts(context);
