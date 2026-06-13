import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';
import { TICKET_OR_SUPPRESSION_PATTERN } from '@critiq/adapter-shared';
import { getCalleeText, getNodeText, walkAst } from '../ast';
import {
  createObservedFact,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const SNAPSHOT_INTENT_COMMENT = /^\s*\/\/\s*snapshot:/;

/** Minimum length for a non-ticket string to be considered a meaningful skip reason. */
const MIN_REASON_LENGTH = 6;

/** x-pattern test keywords where the first argument IS the test name/documentation. */
const X_PATTERNS = new Set(['xit', 'xtest', 'xdescribe']);

const UNIT_TEST_PATH =
  /(?:^|\/)(?:__tests__|spec|test|tests)(?:\/|$)|\.(spec|test)\.(?:[jt]sx?)$/i;
const INTEGRATION_OR_E2E =
  /(?:^|\/)(?:e2e|integration|browser|smoke)(?:\/|$)|[._](?:integration|browser|smoke)[._]/i;
const TEST_INFRASTRUCTURE =
  /(?:^|\/)(?:sandbox|setup)(?:\/|$)/i;

function pathLooksLikeNarrowUnitTest(path: string): boolean {
  return (
    UNIT_TEST_PATH.test(path) &&
    !INTEGRATION_OR_E2E.test(path) &&
    !TEST_INFRASTRUCTURE.test(path)
  );
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
  calleeText: string,
): boolean {
  const isXPattern = X_PATTERNS.has(calleeText);

  for (const arg of call.arguments) {
    if (arg.type === 'Literal' && typeof arg.value === 'string') {
      if (arg.value.length === 0) continue;
      if (isXPattern) return true;
      if (arg.value.length >= MIN_REASON_LENGTH || TICKET_OR_SUPPRESSION_PATTERN.test(arg.value)) return true;
    }
    if (arg.type === 'TemplateLiteral') {
      const text = getNodeText(arg, sourceText) ?? '';
      if (text.length === 0) continue;
      if (isXPattern) return true;
      if (text.length >= MIN_REASON_LENGTH || TICKET_OR_SUPPRESSION_PATTERN.test(text)) return true;
    }
  }
  return false;
}

function precedingLineHasComment(sourceText: string, nodeStart: number): boolean {
  const before = sourceText.slice(0, nodeStart);
  const lines = before.split(/\r?\n/);
  const startIdx = Math.max(0, lines.length - 3);
  for (let i = startIdx; i < lines.length - 1; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('/*')) return true;
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

  if (firstArg?.type === 'ObjectExpression') {
    return false;
  }

  const start = call.range?.[0] ?? 0;
  const prev = previousLineText(sourceText, start);

  return !SNAPSHOT_INTENT_COMMENT.test(prev);
}

const TESTING_LIBRARY_IMPORTS = [
  '@testing-library/react',
  '@testing-library/dom',
  '@testing-library/vue',
  '@testing-library/svelte',
  '@testing-library/angular',
];

const LEGACY_WAITER_NAMES = new Set([
  'wait',
  'waitForElement',
  'waitForDomChange',
]);

function collectTestingLibraryImportSources(
  program: TSESTree.Program,
): Set<string> {
  const sources = new Set<string>();

  walkAst(program, (node) => {
    if (node.type !== 'ImportDeclaration') return;
    if (!TESTING_LIBRARY_IMPORTS.includes(node.source.value)) return;

    for (const spec of node.specifiers) {
      if (
        spec.type === 'ImportSpecifier' &&
        spec.imported.type === 'Identifier'
      ) {
        sources.add(spec.imported.name);
      }
      if (spec.type === 'ImportDefaultSpecifier') {
        sources.add(spec.local.name);
      }
      if (spec.type === 'ImportNamespaceSpecifier') {
        sources.add(spec.local.name);
      }
    }
  });

  return sources;
}

function collectLegacyWaiterFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { path: filePath, sourceText, program, nodeIds } = context;

  if (!pathLooksLikeNarrowUnitTest(filePath)) return facts;

  const testingLibImports = collectTestingLibraryImportSources(program);
  if (testingLibImports.size === 0) return facts;

  walkAst(program, (node) => {
    if (node.type !== 'CallExpression') return;

    const calleeText = getCalleeText(node.callee, sourceText) ?? '';

    if (calleeText === 'waitFor') return;

    const isLegacy = LEGACY_WAITER_NAMES.has(calleeText);

    if (!isLegacy) return;

    if (node.callee.type === 'Identifier') {
      if (!testingLibImports.has(node.callee.name)) return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'testing.legacy-waiter',
        node,
        nodeIds,
        text: getNodeText(node, sourceText),
      }),
    );
  });

  return facts;
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
        skipCallAcceptsReason(node, sourceText, calleeText) ||
        lineContextHasTicket(sourceText, nodeStart) ||
        precedingLineHasComment(sourceText, nodeStart)
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
      const isTimerWithDelay =
        calleeText === 'setTimeout' ||
        calleeText === 'setInterval' ||
        calleeText.endsWith('.setTimeout') ||
        calleeText.endsWith('.setInterval');

      if (isTimerWithDelay) {
        const delayArg = node.arguments[1];
        const isMicroDelay =
          !delayArg ||
          (delayArg.type === 'Literal' &&
            typeof delayArg.value === 'number' &&
            delayArg.value <= 50);

        if (isMicroDelay) {
          return;
        }

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

  facts.push(...collectLegacyWaiterFacts(context));

  return facts;
};
