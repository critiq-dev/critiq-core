import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { FACT_KINDS } from './constants';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { normalizeText } from './text-normalization';

function looksLikeRequestDrivenXmlPayload(text: string): boolean {
  return /\breq(?:uest)?\b/u.test(text) || /\b(?:body|query|params)\b/u.test(text);
}

/** xml2js-style `parseString` on request-driven payloads. */
export function collectXmlParseStringWithUntrustedInputFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || (!calleeText.endsWith('.parseString') && calleeText !== 'parseString')) {
      return;
    }

    const payload = node.arguments[0] as TSESTree.Expression | undefined;
    const payloadText = getNodeText(payload, context.sourceText);

    if (!payloadText || !looksLikeRequestDrivenXmlPayload(payloadText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.xmlParseStringWithUntrustedInput,
        node,
        nodeIds: context.nodeIds,
        text: calleeText,
      }),
    );
  });

  return facts;
}

function isLikelyExpressErrorHandler(
  params: readonly TSESTree.Parameter[],
): boolean {
  if (params.length !== 4) {
    return false;
  }

  const names = params.map((parameter) =>
    parameter.type === 'Identifier' ? parameter.name : '',
  );

  return (
    names[0] === 'err' &&
    names[1] === 'req' &&
    names[2] === 'res' &&
    names[3] === 'next'
  );
}

function handlerSendsErrorToClient(
  body: TSESTree.BlockStatement,
  errName: string,
  sourceText: string,
): boolean {
  let found = false;

  walkAst(body, (node) => {
    if (found || node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, sourceText);

    if (
      calleeText !== 'res.send' &&
      calleeText !== 'res.json' &&
      calleeText !== 'response.send' &&
      calleeText !== 'response.json'
    ) {
      return;
    }

    const firstArgument = node.arguments[0] as TSESTree.Expression | undefined;

    if (
      firstArgument?.type === 'Identifier' &&
      firstArgument.name === errName
    ) {
      found = true;
    }
  });

  return found;
}

/** Express `(err, req, res, next)` handlers that forward `err` to clients. */
export function collectExpressErrorHandlerInformationDisclosureFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'ArrowFunctionExpression' &&
      node.type !== 'FunctionExpression'
    ) {
      return;
    }

    if (!isLikelyExpressErrorHandler(node.params)) {
      return;
    }

    const errParameter = node.params[0];

    if (errParameter.type !== 'Identifier') {
      return;
    }

    const body = node.body;

    if (body.type !== 'BlockStatement') {
      return;
    }

    if (
      !handlerSendsErrorToClient(
        body,
        errParameter.name,
        context.sourceText,
      )
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.expressErrorHandlerInformationDisclosure,
        node,
        nodeIds: context.nodeIds,
        text: 'error middleware',
      }),
    );
  });

  return facts;
}

/** `app.use` with a request-driven mount path before `express.static` (narrow heuristic). */
export function collectExpressUserControlledStaticMountFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText !== 'app.use') {
      return;
    }

    const pathArgument = node.arguments[0] as TSESTree.Expression | undefined;
    const middlewareArgument = node.arguments[1] as
      | TSESTree.Expression
      | undefined;

    if (!pathArgument || !middlewareArgument) {
      return;
    }

    const pathText = getNodeText(pathArgument, context.sourceText);

    if (!pathText || !/\breq(?:uest)?\b/u.test(pathText)) {
      return;
    }

    const middlewareText = normalizeText(
      getNodeText(middlewareArgument, context.sourceText),
    );

    if (!/^express\.static\(/u.test(middlewareText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.expressUserControlledStaticMount,
        node,
        nodeIds: context.nodeIds,
        text: 'app.use',
      }),
    );
  });

  return facts;
}

/** Request-derived computed array indexes (narrow heuristic). */
export function collectRequestDrivenArrayIndexFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'MemberExpression' ||
      !node.computed ||
      node.optional
    ) {
      return;
    }

    const indexText = getNodeText(node.property, context.sourceText);

    if (!indexText || !/\breq(?:uest)?\b/u.test(indexText)) {
      return;
    }

    if (node.object.type !== 'Identifier') {
      return;
    }

    if (node.object.name === 'req' || node.object.name === 'request') {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.requestDrivenArrayIndexAccess,
        node,
        nodeIds: context.nodeIds,
        text: indexText,
      }),
    );
  });

  return facts;
}
