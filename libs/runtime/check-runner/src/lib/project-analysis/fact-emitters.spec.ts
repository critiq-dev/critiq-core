import type {
  AnalyzedFile,
  ObservedFact,
  ObservedRange,
} from '@critiq/core-rules-engine';
import { analyzeTypeScriptFile } from '@critiq/adapter-typescript';

import { createFileContexts } from './context';
import {
  emitDuplicateCodeFacts,
  emitLogicChangeWithoutTestsFacts,
  emitMissingAuthorizationFacts,
  emitMissingBatchFacts,
  emitMissingOwnershipFacts,
  emitMissingTestsFacts,
  emitRepeatedIoFacts,
  emitTightCouplingFacts,
} from './fact-emitters';

function analyze(
  path: string,
  text: string,
  changedRanges?: ObservedRange[],
): AnalyzedFile {
  const result = analyzeTypeScriptFile(path, text);

  if (!result.success) {
    throw new Error(
      `Expected TypeScript analysis to succeed for ${path}: ${JSON.stringify(
        result.diagnostics,
      )}`,
    );
  }

  return {
    ...result.data,
    changedRanges,
  };
}

function factsOf(file: AnalyzedFile, kind?: string): ObservedFact[] {
  const facts = file.semantics?.controlFlow?.facts ?? [];

  return kind ? facts.filter((fact) => fact.kind === kind) : facts;
}

describe('project analysis fact emitters', () => {
  it('emits missing authorization and ownership findings while respecting ownership guards', () => {
    const files = [
      analyze(
        'src/api/admin.ts',
        [
          'export async function removeAccount() {',
          '  return deleteUser();',
          '}',
        ].join('\n'),
      ),
      analyze(
        'src/api/accounts.ts',
        [
          'export async function issueRefund(req: { user: unknown; body: { accountId: string } }) {',
          '  authorize(req.user);',
          '  return refundPayment(req.body.accountId);',
          '}',
        ].join('\n'),
      ),
      analyze(
        'src/api/safe.ts',
        [
          'export async function issueSafeRefund(req: { user: unknown; body: { accountId: string } }) {',
          '  authorize(req.user);',
          '  requireOwnership(req.body.accountId);',
          '  return refundPayment(req.body.accountId);',
          '}',
        ].join('\n'),
      ),
    ];
    const contexts = createFileContexts(files);

    emitMissingAuthorizationFacts(contexts);
    emitMissingOwnershipFacts(contexts);

    expect(
      factsOf(files[0], 'security.missing-authorization-before-sensitive-action'),
    ).toHaveLength(1);
    expect(factsOf(files[1], 'security.missing-ownership-validation')).toHaveLength(
      1,
    );
    expect(factsOf(files[2], 'security.missing-ownership-validation')).toHaveLength(
      0,
    );
    expect(
      factsOf(files[2], 'security.missing-authorization-before-sensitive-action'),
    ).toHaveLength(0);
  });

  it('emits repeated IO and missing batch-operation facts for looped helper calls', () => {
    const file = analyze(
      'src/services/hydrate-users.ts',
      [
        'const db = {',
        '  query: async (_value: unknown) => [],',
        '};',
        '',
        'async function loadUser(id: string) {',
        '  return db.query(id);',
        '}',
        '',
        'async function loadUsersBatch(ids: string[]) {',
        '  return db.query(ids);',
        '}',
        '',
        'export async function hydrateUsers(ids: string[]) {',
        '  for (const id of ids) {',
        '    await loadUser(id);',
        '  }',
        '}',
      ].join('\n'),
    );
    const contexts = createFileContexts([file]);

    emitRepeatedIoFacts(contexts);
    emitMissingBatchFacts(contexts);

    expect(factsOf(file, 'performance.repeated-io-in-loop')).toEqual([
      expect.objectContaining({
        text: expect.stringContaining('loadUser'),
      }),
    ]);
    expect(factsOf(file, 'performance.missing-batch-operations')).toEqual([
      expect.objectContaining({
        props: {
          batchHelperName: 'loadUsersBatch',
        },
      }),
    ]);
  });

  it('emits duplicate-code and tight-coupling facts across matching modules', () => {
    const duplicatedFunctionLines = [
      'export function summarizeInvoice(invoice: { lineItems: Array<{ amount: number }> }) {',
      '  const subtotal = invoice.lineItems.reduce((sum, item) => sum + item.amount, 0);',
      '  const taxes = subtotal * 0.15;',
      '  const serviceFee = subtotal * 0.05;',
      '  const discount = subtotal > 1000 ? 25 : 0;',
      '  const grandTotal = subtotal + taxes + serviceFee - discount;',
      "  const auditMessage = `subtotal:${subtotal}:taxes:${taxes}:fee:${serviceFee}:discount:${discount}:total:${grandTotal}`;",
      '  return { subtotal, taxes, serviceFee, discount, grandTotal, auditMessage };',
      '}',
    ];
    const files = [
      analyze(
        'src/modules/a.ts',
        [
          "import { createBLabel } from './b';",
          '',
          'export function createALabel() {',
          '  return createBLabel();',
          '}',
          '',
          ...duplicatedFunctionLines,
        ].join('\n'),
      ),
      analyze(
        'src/modules/b.ts',
        [
          "import { createALabel } from './a';",
          '',
          'export function createBLabel() {',
          '  return createALabel();',
          '}',
          '',
          ...duplicatedFunctionLines,
        ].join('\n'),
      ),
    ];
    const contexts = createFileContexts(files);

    emitDuplicateCodeFacts(contexts);
    emitTightCouplingFacts(contexts);

    expect(factsOf(files[0], 'quality.duplicate-code-block')).toHaveLength(1);
    expect(factsOf(files[1], 'quality.duplicate-code-block')).toHaveLength(1);
    expect(factsOf(files[0], 'quality.tight-module-coupling')).toEqual([
      expect.objectContaining({
        props: {
          peerPath: 'src/modules/b.ts',
        },
      }),
    ]);
    expect(factsOf(files[1], 'quality.tight-module-coupling')).toEqual([
      expect.objectContaining({
        props: {
          peerPath: 'src/modules/a.ts',
        },
      }),
    ]);
  });

  it('emits missing-test heuristics only for uncovered critical logic changes', () => {
    const changedRange = [
      {
        startLine: 1,
        startColumn: 1,
        endLine: 1,
        endColumn: Number.MAX_SAFE_INTEGER,
      },
    ] satisfies ObservedRange[];
    const files = [
      analyze(
        'src/services/payout-service.ts',
        [
          'export async function issuePayout(accountId: string) {',
          "  const payout = accountId;",
          '  return transferFunds(payout);',
          '}',
        ].join('\n'),
        changedRange,
      ),
      analyze(
        'src/services/payment-service.ts',
        [
          'export async function transferPayment(accountId: string) {',
          "  const payment = accountId;",
          '  return refundPayment(payment);',
          '}',
        ].join('\n'),
        changedRange,
      ),
      analyze(
        'src/services/payment-service.test.ts',
        [
          "import { transferPayment } from './payment-service';",
          '',
          "it('transfers payments', async () => {",
          "  await expect(transferPayment('acct-1')).resolves.toBeDefined();",
          '});',
        ].join('\n'),
        changedRange,
      ),
      analyze(
        'src/services/__fixtures__/payment-fixture.ts',
        [
          'export async function issuePayoutFixture(accountId: string) {',
          '  return transferFunds(accountId);',
          '}',
        ].join('\n'),
        changedRange,
      ),
    ];
    const contexts = createFileContexts(files);

    emitMissingTestsFacts(contexts);
    emitLogicChangeWithoutTestsFacts(contexts);

    expect(
      factsOf(files[0], 'quality.missing-tests-for-critical-logic'),
    ).toHaveLength(1);
    expect(
      factsOf(files[0], 'quality.logic-change-without-test-updates'),
    ).toHaveLength(1);
    expect(
      factsOf(files[1], 'quality.missing-tests-for-critical-logic'),
    ).toHaveLength(0);
    expect(
      factsOf(files[1], 'quality.logic-change-without-test-updates'),
    ).toHaveLength(0);
    expect(
      factsOf(files[3], 'quality.missing-tests-for-critical-logic'),
    ).toHaveLength(0);
    expect(
      factsOf(files[3], 'quality.logic-change-without-test-updates'),
    ).toHaveLength(0);
  });
});
