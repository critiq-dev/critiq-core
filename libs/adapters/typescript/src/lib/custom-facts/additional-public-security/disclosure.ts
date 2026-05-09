import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { collectDisclosureSignals } from '../disclosure-signals';
import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  isFunctionLike,
  type FunctionLikeNode,
  type TypeScriptFactDetectorContext,
  walkAstWithAncestors,
} from '../shared';
import {
  resolveFunctionBindings,
  resolveFunctionLike,
} from './analysis';
import { FACT_KINDS } from './constants';
import { getLiteralString } from './literal-values';

// Recognize the common Node.js logger families so disclosure findings catch
// stack/header/cookie/env data leaked through pino, winston, bunyan, or
// consola in addition to the built-in console/logger/log identifiers.
const informationLeakageSinkPattern =
  /^(?:console|logger|log|pino|winston|bunyan|consola)\.(?:debug|error|info|log|warn|trace)$/u;
const responseLeakageSinks = new Set([
  'res.end',
  'res.json',
  'res.send',
  'res.write',
]);
const debugMiddlewarePattern = /(?:^|\.)(?:errorhandler|errorHandler)$/u;
const debugRoutePattern =
  /^\/(?:(?:__)?debug|diagnostics?|stack(?:trace)?|env|pprof)(?:\/|$)/iu;
const routeRegistrationPattern = /(?:^|\.)(all|delete|get|head|options|patch|post|put|use)$/u;

function normalizeExpressionText(text: string | undefined): string {
  return text?.replace(/\s+/gu, ' ').trim() ?? '';
}

function isExplicitDevOnlyTest(
  node: TSESTree.Expression,
  sourceText: string,
): boolean {
  const text = normalizeExpressionText(getNodeText(node, sourceText));

  return (
    /^process\.env\.NODE_ENV\s*!={1,2}\s*['"]production['"]$/u.test(text) ||
    /^process\.env\.NODE_ENV\s*={2,3}\s*['"]development['"]$/u.test(text) ||
    /^import\.meta\.env\.DEV$/u.test(text) ||
    /^__DEV__$/u.test(text)
  );
}

export function isExplicitDevOnlyContext(
  node: TSESTree.Node,
  ancestors: readonly TSESTree.Node[],
  sourceText: string,
): boolean {
  let child: TSESTree.Node = node;

  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];

    if (
      ancestor.type === 'IfStatement' &&
      ancestor.consequent === child &&
      isExplicitDevOnlyTest(ancestor.test, sourceText)
    ) {
      return true;
    }

    if (
      ancestor.type === 'ConditionalExpression' &&
      ancestor.consequent === child &&
      isExplicitDevOnlyTest(ancestor.test, sourceText)
    ) {
      return true;
    }

    if (
      ancestor.type === 'LogicalExpression' &&
      ancestor.operator === '&&' &&
      ancestor.right === child &&
      isExplicitDevOnlyTest(ancestor.left, sourceText)
    ) {
      return true;
    }

    child = ancestor;
  }

  return false;
}

function getInformationLeakagePayloads(
  node: TSESTree.CallExpression,
  calleeText: string,
): TSESTree.Expression[] {
  if (calleeText === 'process.stdout.write' || calleeText === 'process.stderr.write') {
    const payload = node.arguments[0];

    return payload && payload.type !== 'SpreadElement' ? [payload] : [];
  }

  if (responseLeakageSinks.has(calleeText)) {
    const payload = node.arguments[0];

    return payload && payload.type !== 'SpreadElement' ? [payload] : [];
  }

  return node.arguments.filter(
    (argument): argument is TSESTree.Expression =>
      argument.type !== 'SpreadElement',
  );
}

function collectHandlerLeakageSignals(
  handler: FunctionLikeNode,
  context: TypeScriptFactDetectorContext,
): string[] {
  const signals = new Set<string>();

  walkAstWithAncestors(handler.body, (node, ancestors) => {
    if (
      ancestors.some(
        (ancestor) => isFunctionLike(ancestor) && ancestor !== handler,
      )
    ) {
      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    if (isExplicitDevOnlyContext(node, ancestors, context.sourceText)) {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !responseLeakageSinks.has(calleeText)) {
      return;
    }

    const payload = node.arguments[0];

    if (!payload || payload.type === 'SpreadElement') {
      return;
    }

    for (const signal of collectDisclosureSignals(payload, context.sourceText, {
      includeDiagnostics: true,
    })) {
      signals.add(signal);
    }
  });

  return [...signals];
}

function normalizeDisclosureSignals(signals: readonly string[]): string[] {
  const uniqueSignals = [...new Set(signals)];

  if (uniqueSignals.length === 1 && uniqueSignals[0] === 'error') {
    return [];
  }

  return uniqueSignals;
}

function isDebugMiddlewareArgument(
  argument:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | TSESTree.SpreadElement
    | undefined,
  sourceText: string,
): boolean {
  if (!argument || argument.type === 'SpreadElement') {
    return false;
  }

  if (argument.type !== 'CallExpression') {
    return false;
  }

  const calleeText = getCalleeText(argument.callee, sourceText);

  return Boolean(calleeText && debugMiddlewarePattern.test(calleeText));
}

export function collectInformationLeakageFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      !calleeText ||
      !(
        informationLeakageSinkPattern.test(calleeText) ||
        responseLeakageSinks.has(calleeText) ||
        calleeText === 'process.stdout.write' ||
        calleeText === 'process.stderr.write'
      )
    ) {
      return;
    }

    if (isExplicitDevOnlyContext(node, ancestors, context.sourceText)) {
      return;
    }

    const disclosureSignals = normalizeDisclosureSignals(
      getInformationLeakagePayloads(node, calleeText)
      .flatMap((payload) =>
        collectDisclosureSignals(payload, context.sourceText, {
          includeDiagnostics: true,
        }),
      )
      .filter((signal, index, allSignals) => allSignals.indexOf(signal) === index),
    );

    if (disclosureSignals.length === 0) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.informationLeakage,
        node,
        nodeIds: context.nodeIds,
        props: {
          disclosureSignals,
          sink: calleeText,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

export function collectDebugModeEnabledFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const functionBindings = resolveFunctionBindings(context);

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !routeRegistrationPattern.test(calleeText)) {
      return;
    }

    if (isExplicitDevOnlyContext(node, ancestors, context.sourceText)) {
      return;
    }

    const pathArgument = getLiteralString(
      node.arguments[0] as TSESTree.Expression | undefined,
    );
    const hasDebugPath = Boolean(pathArgument && debugRoutePattern.test(pathArgument));
    const hasDebugMiddleware = node.arguments.some((argument) =>
      isDebugMiddlewareArgument(argument, context.sourceText),
    );
    const handlerArguments = node.arguments
      .slice(typeof pathArgument === 'string' ? 1 : 0)
      .map((argument) =>
        resolveFunctionLike(
          argument as TSESTree.Expression | TSESTree.SpreadElement | undefined,
          functionBindings,
        ),
      )
      .filter((handler): handler is FunctionLikeNode => Boolean(handler));
    const handlerSignals = new Set(
      handlerArguments.flatMap((handler) =>
        collectHandlerLeakageSignals(handler, context),
      ),
    );

    if (!hasDebugPath && !hasDebugMiddleware && handlerSignals.size === 0) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.debugModeEnabled,
        node,
        nodeIds: context.nodeIds,
        props: {
          debugPath: pathArgument,
          disclosureSignals: [...handlerSignals].sort(),
          sink: calleeText,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}
