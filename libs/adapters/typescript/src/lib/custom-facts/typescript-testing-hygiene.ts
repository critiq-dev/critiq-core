import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';
import { TICKET_OR_SUPPRESSION_PATTERN } from '@critiq/adapter-shared';
import { getCalleeText, getNodeText, walkAst } from '../ast';
import {
  createObservedFact,
  type TypeScriptFactDetector,
} from './shared';

const SNAPSHOT_INTENT_COMMENT = /^\s*\/\/\s*snapshot:/;

const UNIT_TEST_PATH =
  /(?:^|\/)(?:__tests__|spec|test|tests)(?:\/|$)|\.(spec|test)\.(?:[jt]sx?)$/i;
const INTEGRATION_OR_E2E =
  /(?:^|\/)(?:e2e|integration)(?:\/|$)|[._]integration[._]/i;

function pathLooksLikeNarrowUnitTest(path: string): boolean {
  return UNIT_TEST_PATH.test(path) && !INTEGRATION_OR_E2E.test(path);
}

function lineContextHasTicket(sourceText: string, nodeStart: number): boolean {
  const before = sourceText.slice(0, nodeStart);
  const lines = before.split(/\r?\n/);
  const prevLine = lines.length >= 2 ? (lines[lines.length - 2] ?? '') : '';
  const sameLinePrefix = lines[lines.length - 1] ?? '';
  const restOfLine = sourceText.slice(nodeStart).split(/\r?\n/, 1)[0] ?? '';

  return (
    TICKET_OR_SUPPRESSION_PATTERN.test(`${prevLine}\n${sameLinePrefix}`) ||
    TICKET_OR_SUPPRESSION_PATTERN.test(restOfLine)
  );
}

function previousLineText(sourceText: string, nodeStart: number): string {
  const before = sourceText.slice(0, nodeStart).trimEnd();
  const lastNl = before.lastIndexOf('\n');

  return lastNl < 0 ? '' : before.slice(0, lastNl).split(/\r?\n/).pop() ?? '';
}

function calleeIndicatesFocusedOnly(calleeText: string | undefined): boolean {
  if (!calleeText) {
    return false;
  }

  if (!calleeText.endsWith('.only')) {
    return false;
  }

  const root = calleeText.replace(/\.only$/u, '').split('.').pop() ?? '';

  return [
    'it',
    'test',
    'describe',
    'suite',
    'context',
    'fixture',
    'beforeEach',
    'afterEach',
  ].includes(root);
}

function calleeIndicatesSkip(calleeText: string | undefined): boolean {
  if (!calleeText) {
    return false;
  }

  if (['xit', 'xtest', 'xdescribe'].includes(calleeText)) {
    return true;
  }

  if (!calleeText.endsWith('.skip')) {
    return false;
  }

  const root = calleeText.replace(/\.skip$/u, '').split('.').pop() ?? '';

  return ['it', 'test', 'describe', 'suite', 'context', 'fixture'].includes(
    root,
  );
}

function skipCallAcceptsReason(
  call: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const first = call.arguments[0];
  if (!first) {
    return false;
  }

  if (first.type === 'Literal' && typeof first.value === 'string') {
    return TICKET_OR_SUPPRESSION_PATTERN.test(first.value);
  }

  if (first.type === 'TemplateLiteral') {
    return TICKET_OR_SUPPRESSION_PATTERN.test(getNodeText(first, sourceText) ?? '');
  }

  return false;
}

function isSnapshotMatcherCall(
  call: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const calleeText = getCalleeText(call.callee, sourceText) ?? '';

  return (
    calleeText.endsWith('.toMatchSnapshot') ||
    calleeText.endsWith('.toMatchInlineSnapshot') ||
    calleeText === 'toMatchSnapshot' ||
    calleeText === 'toMatchInlineSnapshot'
  );
}

function snapshotCallLacksIntent(
  call: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  if (!isSnapshotMatcherCall(call, sourceText)) {
    return false;
  }

  const firstArg = call.arguments[0];
  if (firstArg?.type === 'Literal' && typeof firstArg.value === 'string') {
    return false;
  }

  if (firstArg?.type === 'TemplateLiteral') {
    return false;
  }

  const start = call.range?.[0] ?? 0;
  const prev = previousLineText(sourceText, start);

  return !SNAPSHOT_INTENT_COMMENT.test(prev);
}

export const collectTypescriptTestingHygieneFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { path: filePath, sourceText, program, nodeIds } = context;
  const isTest = pathLooksLikeNarrowUnitTest(filePath);
  const fakeTimers = /\b(?:jest|vi)\.useFakeTimers\s*\(/.test(sourceText);

  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, sourceText) ?? '';
    const nodeStart = node.range?.[0] ?? 0;

    if (isTest && calleeIndicatesFocusedOnly(calleeText)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'testing.focused-only-invocation',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );

      return;
    }

    if (isTest && calleeIndicatesSkip(calleeText)) {
      if (
        skipCallAcceptsReason(node, sourceText) ||
        lineContextHasTicket(sourceText, nodeStart)
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'testing.skipped-without-ticket-reference',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );

      return;
    }

    if (isTest && snapshotCallLacksIntent(node, sourceText)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'testing.snapshot-without-review-intent',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
        }),
      );

      return;
    }

    if (isTest && !fakeTimers) {
      const wallClockCallee =
        calleeText === 'setTimeout' ||
        calleeText === 'setInterval' ||
        calleeText === 'Date.now' ||
        calleeText.endsWith('.setTimeout') ||
        calleeText.endsWith('.setInterval') ||
        calleeText === 'performance.now' ||
        calleeText.endsWith('.performance.now');

      if (wallClockCallee) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'testing.flaky-timer-in-test',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );

        return;
      }
    }

    if (isTest) {
      const networkCallee =
        calleeText === 'fetch' ||
        calleeText === 'http.request' ||
        calleeText === 'https.request' ||
        calleeText.endsWith('.request') ||
        /^axios\.(delete|get|head|options|patch|post|put)$/i.test(calleeText);

      if (networkCallee) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'testing.real-network-in-unit-test',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }
    }
  });

  return facts;
};
