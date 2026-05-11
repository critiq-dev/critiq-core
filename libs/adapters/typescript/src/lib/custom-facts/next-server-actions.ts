import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from './shared';

import { FACT_KINDS } from './additional-public-security/constants';

const ACTIONS_FILE_PATTERN = /(?:^|\/)actions\.(ts|tsx)$/u;

const KNOWN_DIRECTIVE_LITERALS = new Set(['use strict', 'use asm', 'use server']);

const LOCAL_AUTH_EVIDENCE =
  /\b(auth|getServerSession|getSession|requireAuth|requireUser|assertAuthenticated|permissions?|authorize)\b/u;

function statementsDeclareUseServer(
  statements: ReadonlyArray<TSESTree.Statement>,
): boolean {
  for (const statement of statements) {
    if (
      statement.type !== 'ExpressionStatement' ||
      statement.expression.type !== 'Literal' ||
      typeof statement.expression.value !== 'string'
    ) {
      break;
    }

    if (!KNOWN_DIRECTIVE_LITERALS.has(statement.expression.value)) {
      break;
    }

    if (statement.expression.value === 'use server') {
      return true;
    }
  }

  return false;
}

function fileDeclaresUseServer(program: TSESTree.Program): boolean {
  return statementsDeclareUseServer(program.body);
}

function functionDeclaresUseServer(
  fn:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
): boolean {
  if (fn.body.type !== 'BlockStatement') {
    return false;
  }

  return statementsDeclareUseServer(fn.body.body);
}

function collectMutationCalls(
  body: TSESTree.BlockStatement,
  sourceText: string,
): TSESTree.CallExpression[] {
  const mutations: TSESTree.CallExpression[] = [];

  walkAst(body, (candidate: TSESTree.Node) => {
    if (candidate.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(candidate.callee, sourceText);

    if (!calleeText) {
      return;
    }

    if (
      /\.(?:delete|create|update|upsert)\b/u.test(calleeText) ||
      /\.(?:sendMail|send_email)\b/u.test(calleeText) ||
      /\b(?:writeFile|appendFile|unlink)\b/u.test(calleeText) ||
      /\bpaymentIntents\.create\b/u.test(calleeText)
    ) {
      mutations.push(candidate);
    }
  });

  return mutations;
}

function mutationHasPrecedingAuthEvidence(
  functionStartOffset: number,
  mutation: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const mutationStart = mutation.range?.[0] ?? sourceText.length;

  return LOCAL_AUTH_EVIDENCE.test(
    sourceText.slice(functionStartOffset, mutationStart),
  );
}

function resolveIssueNode(
  fn:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
  mutation: TSESTree.CallExpression,
): TSESTree.Node {
  if (fn.type === 'FunctionDeclaration' && fn.id) {
    return fn.id;
  }

  return mutation;
}

function inspectAsyncServerFunction(
  fn:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
  context: TypeScriptFactDetectorContext,
  fileDirective: boolean,
  facts: ObservedFact[],
): void {
  if (!fn.async || fn.body.type !== 'BlockStatement') {
    return;
  }

  const scopedDirective = fileDirective || functionDeclaresUseServer(fn);

  if (!scopedDirective) {
    return;
  }

  const mutations = collectMutationCalls(fn.body, context.sourceText);

  if (mutations.length === 0) {
    return;
  }

  mutations.sort(
    (left, right) => (left.range?.[0] ?? 0) - (right.range?.[0] ?? 0),
  );

  const firstMutation = mutations[0];
  const functionStart = fn.range?.[0] ?? 0;

  if (mutationHasPrecedingAuthEvidence(functionStart, firstMutation, context.sourceText)) {
    return;
  }

  facts.push(
    createObservedFact({
      appliesTo: 'function',
      kind: FACT_KINDS.nextServerActionMissingLocalAuth,
      node: resolveIssueNode(fn, firstMutation),
      nodeIds: context.nodeIds,
      text: getCalleeText(firstMutation.callee, context.sourceText) ?? 'mutation',
    }),
  );
}

export function collectNextServerActionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!ACTIONS_FILE_PATTERN.test(context.path)) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const fileDirective = fileDeclaresUseServer(context.program);

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type === 'FunctionDeclaration') {
      inspectAsyncServerFunction(node, context, fileDirective, facts);

      return;
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.init &&
      (node.init.type === 'ArrowFunctionExpression' ||
        node.init.type === 'FunctionExpression')
    ) {
      inspectAsyncServerFunction(node.init, context, fileDirective, facts);
    }
  });

  return facts;
}
