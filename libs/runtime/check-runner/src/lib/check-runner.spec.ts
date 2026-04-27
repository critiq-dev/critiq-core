import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  createDefaultSourceAdapterRegistry,
  runCheckCommand,
} from './check-runner';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-check-runner-'));
}

function writeWorkspaceFile(
  rootDirectory: string,
  relativePath: string,
  content: string,
): void {
  const absolutePath = join(rootDirectory, relativePath);
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, 'utf8');
}

function runGitCommand(rootDirectory: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd: rootDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function initializeGitRepository(rootDirectory: string): void {
  runGitCommand(rootDirectory, ['init']);
  runGitCommand(rootDirectory, ['config', 'user.email', 'test@example.com']);
  runGitCommand(rootDirectory, ['config', 'user.name', 'Critiq Test']);
}

function commitAll(rootDirectory: string, message: string): void {
  runGitCommand(rootDirectory, ['add', '.']);
  runGitCommand(rootDirectory, ['commit', '-m', message, '--no-gpg-sign']);
}

const noConsoleLogRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.logging.no-console-log',
  '  title: Avoid console.log',
  '  summary: Use the project logger instead of console.log.',
  '  rationale: Console logging bypasses the shared logger pipeline.',
  '  tags:',
  '    - logging',
  '    - rules-catalog',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  node:',
  '    kind: CallExpression',
  '    bind: call',
  '    where:',
  '      - path: callee.object.text',
  '        equals: console',
  '      - path: callee.property.text',
  '        equals: log',
  'emit:',
  '  finding:',
  '    category: maintainability',
  '    severity: low',
  '    confidence: high',
  '    tags:',
  '      - logging',
  '  message:',
  '    title: Avoid `${captures.call.text}`',
  '    summary: Use the project logger instead of `${captures.call.text}`.',
  '  remediation:',
  '    summary: Replace `${captures.call.text}` with the logger.',
].join('\n');

const tightModuleCouplingRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.quality.tight-module-coupling',
  '  title: Tight coupling between modules',
  '  summary: Direct import cycles between modules increase coupling.',
  '  rationale: Cyclic dependencies complicate initialization order and testing.',
  '  tags:',
  '    - quality',
  '    - architecture',
  '  appliesTo: project',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  fact:',
  '    kind: quality.tight-module-coupling',
  '    bind: issue',
  'emit:',
  '  finding:',
  '    category: quality.architecture',
  '    severity: medium',
  '    confidence: 0.9',
  '  message:',
  '    title: Break direct cyclic imports between modules',
  '    summary: "`${captures.issue.text}` participates in a direct import cycle."',
  '  remediation:',
  '    summary: Extract a shared dependency to remove the cycle.',
].join('\n');

const frontendOnlyAuthorizationRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.security.frontend-only-authorization',
  '  title: Authorization enforced only on frontend',
  '  summary: Backend routes should enforce authorization directly.',
  '  rationale: Frontend checks are easy to bypass.',
  '  tags:',
  '    - security',
  '    - authorization',
  '  appliesTo: project',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  fact:',
  '    kind: security.frontend-only-authorization',
  '    bind: issue',
  'emit:',
  '  finding:',
  '    category: security.authorization',
  '    severity: high',
  '    confidence: 0.65',
  '  message:',
  '    title: Backend authorization must not live only in the frontend',
  '    summary: "Route `${captures.issue.text}` appears gated only in frontend code."',
  '  remediation:',
  '    summary: Add a backend authorization check on the route.',
].join('\n');

const logicChangeWithoutTestsRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.quality.logic-change-without-test-updates',
  '  title: Logic change without corresponding test updates',
  '  summary: Diffs that change critical logic should usually update the matching tests.',
  '  rationale: Critical logic changes without tests are regression-prone.',
  '  tags:',
  '    - quality',
  '    - testing',
  '  appliesTo: project',
  'scope:',
  '  languages:',
  '    - typescript',
  '  changedLinesOnly: true',
  'match:',
  '  fact:',
  '    kind: quality.logic-change-without-test-updates',
  '    bind: issue',
  'emit:',
  '  finding:',
  '    category: quality.testing',
  '    severity: medium',
  '    confidence: 0.7',
  '  message:',
  '    title: Update tests alongside critical logic changes',
  '    summary: "`${captures.issue.text}` changed without a corresponding test change."',
  '  remediation:',
  '    summary: Update the matching tests in the same diff.',
].join('\n');

const missingTestsForCriticalLogicRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.quality.missing-tests-for-critical-logic',
  '  title: Missing tests for critical logic',
  '  summary: Critical auth, payment, or similar business logic should have a matching test file.',
  '  rationale: Important business logic needs direct regression coverage.',
  '  tags:',
  '    - quality',
  '    - testing',
  '  appliesTo: project',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  fact:',
  '    kind: quality.missing-tests-for-critical-logic',
  '    bind: issue',
  'emit:',
  '  finding:',
  '    category: quality.testing',
  '    severity: medium',
  '    confidence: 0.8',
  '  message:',
  '    title: Add tests for critical logic paths',
  '    summary: "`${captures.issue.text}` looks like critical logic but no matching test file was found."',
  '  remediation:',
  '    summary: Add a focused unit or integration test that covers the critical behavior.',
].join('\n');

describe('check runner', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
    writeWorkspaceFile(
      tempDirectory,
      '.critiq/config.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: CritiqConfig',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/package.json',
      JSON.stringify({
        name: '@critiq/rules',
        version: '0.0.1',
        main: './index.js',
      }),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/index.js',
      'module.exports = {};\n',
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.logging.no-console-log',
        '    rulePath: ./rules/ts.logging.no-console-log.rule.yaml',
        '    presets:',
        '      - recommended',
        '      - strict',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.logging.no-console-log.rule.yaml',
      noConsoleLogRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/example.ts',
      'console.log("hello");\n',
    );
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('registers the default OSS adapter set', () => {
    const registry = createDefaultSourceAdapterRegistry();

    expect(registry.findAdapterForPath('src/example.ts')).toBeDefined();
    expect(registry.findAdapterForPath('src/example.py')).toBeUndefined();
  });

  it('runs the catalog-backed check workflow through the adapter registry', () => {
    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.catalogPackage).toBe('@critiq/rules');
    expect(result.envelope.matchedRuleCount).toBe(1);
    expect(result.envelope.findingCount).toBe(1);
    expect(result.envelope.findings[0].rule.id).toBe('ts.logging.no-console-log');
    expect(result.envelope.provenance).toEqual(
      expect.objectContaining({
        engineKind: 'critiq-cli',
        engineVersion: '0.0.1',
        rulePack: '@critiq/rules',
      }),
    );
    expect(result.envelope.findings[0]).toEqual(
      expect.not.objectContaining({
        provenance: expect.anything(),
      }),
    );
    expect(result.envelope.findings[0].fingerprints).toEqual({
      primary: expect.any(String),
    });
  });

  it('uses default settings when the repo config is missing', () => {
    rmSync(join(tempDirectory, '.critiq'), { recursive: true, force: true });

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.catalogPackage).toBe('@critiq/rules');
    expect(result.envelope.preset).toBe('recommended');
    expect(result.envelope.matchedRuleCount).toBe(1);
    expect(result.envelope.findingCount).toBe(1);
    expect(result.envelope.diagnostics).toEqual([]);
  });

  it('ignores unit test files unless config opts in', () => {
    rmSync(join(tempDirectory, 'src'), { recursive: true, force: true });
    writeWorkspaceFile(
      tempDirectory,
      'src/example.test.ts',
      'console.log("hello");\n',
    );

    const defaultResult = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(defaultResult.envelope.scannedFileCount).toBe(0);
    expect(defaultResult.envelope.findingCount).toBe(0);

    writeWorkspaceFile(
      tempDirectory,
      '.critiq/config.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: CritiqConfig',
        'includeTests: true',
      ].join('\n'),
    );

    const optedInResult = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(optedInResult.envelope.scannedFileCount).toBe(1);
    expect(optedInResult.envelope.findingCount).toBe(1);
  });

  it('adds repo-level project facts before evaluating cross-file rules', () => {
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.quality.tight-module-coupling',
        '    rulePath: ./rules/ts.quality.tight-module-coupling.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.quality.tight-module-coupling.rule.yaml',
      tightModuleCouplingRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/modules/cycle-a.ts',
      [
        "import { createBLabel } from './cycle-b';",
        '',
        'export function createALabel(name: string) {',
        '  return `a:${createBLabel(name)}`;',
        '}',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/modules/cycle-b.ts',
      [
        "import { createALabel } from './cycle-a';",
        '',
        'export function createBLabel(name: string) {',
        '  return `b:${createALabel(name)}`;',
        '}',
      ].join('\n'),
    );

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.findingCount).toBe(2);
    expect(result.envelope.findings.map((finding) => finding.rule.id)).toEqual([
      'ts.quality.tight-module-coupling',
      'ts.quality.tight-module-coupling',
    ]);
    expect(
      result.envelope.findings.map((finding) => finding.locations.primary.path),
    ).toEqual(['src/modules/cycle-a.ts', 'src/modules/cycle-b.ts']);
  });

  it('matches sibling and index-based tests while skipping fixture-like directories', () => {
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.quality.missing-tests-for-critical-logic',
        '    rulePath: ./rules/ts.quality.missing-tests-for-critical-logic.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.quality.missing-tests-for-critical-logic.rule.yaml',
      missingTestsForCriticalLogicRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payment-service.ts',
      [
        'export async function transferPayment(accountId: string) {',
        "  return `payment:${accountId}`;",
        '}',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payment-service.spec.ts',
      [
        "import { transferPayment } from './payment-service';",
        '',
        "it('transfers payments', async () => {",
        "  await expect(transferPayment('acct-1')).resolves.toBe('payment:acct-1');",
        '});',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/refund/index.ts',
      [
        'export async function issueRefund(refundId: string) {',
        "  return `refund:${refundId}`;",
        '}',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/refund.spec.ts',
      [
        "import { issueRefund } from './refund';",
        '',
        "it('issues refunds', async () => {",
        "  await expect(issueRefund('refund-1')).resolves.toBe('refund:refund-1');",
        '});',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/__data__/index.ts',
      [
        'export async function buildPaymentFixtures() {',
        "  return ['payment:fixture'];",
        '}',
      ].join('\n'),
    );

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.findingCount).toBe(0);
  });

  it('flags critical logic without a matching test file', () => {
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.quality.missing-tests-for-critical-logic',
        '    rulePath: ./rules/ts.quality.missing-tests-for-critical-logic.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.quality.missing-tests-for-critical-logic.rule.yaml',
      missingTestsForCriticalLogicRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payout-service.ts',
      [
        'export async function issuePayout(accountId: string) {',
        "  return `payout:${accountId}`;",
        '}',
      ].join('\n'),
    );

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.findingCount).toBe(1);
    expect(result.envelope.findings[0].rule.id).toBe(
      'ts.quality.missing-tests-for-critical-logic',
    );
    expect(result.envelope.findings[0].locations.primary.path).toBe(
      'src/services/payout-service.ts',
    );
  });

  it('correlates frontend-gated routes with unguarded backend handlers', () => {
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.security.frontend-only-authorization',
        '    rulePath: ./rules/ts.security.frontend-only-authorization.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.security.frontend-only-authorization.rule.yaml',
      frontendOnlyAuthorizationRule,
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/api/staff.ts',
      [
        'const router = {',
        '  get: (_path: string, handler: unknown) => handler,',
        '};',
        '',
        "router.get('/staff/users', async () => ['ada']);",
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/frontend/staff.tsx',
      [
        'const session = {',
        "  user: { id: 'employee-1' },",
        '};',
        '',
        'export async function loadDirectory() {',
        '  if (!session.user) {',
        '    return [];',
        '  }',
        '',
        "  return fetch('/staff/users');",
        '}',
      ].join('\n'),
    );

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
    });

    expect(result.envelope.findingCount).toBe(1);
    expect(result.envelope.findings[0].rule.id).toBe(
      'ts.security.frontend-only-authorization',
    );
    expect(result.envelope.findings[0].locations.primary.path).toBe(
      'src/api/staff.ts',
    );
  });

  it('flags changed critical logic when the diff has no matching test updates', () => {
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.quality.logic-change-without-test-updates',
        '    rulePath: ./rules/ts.quality.logic-change-without-test-updates.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.quality.logic-change-without-test-updates.rule.yaml',
      logicChangeWithoutTestsRule,
    );
    initializeGitRepository(tempDirectory);
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payment-service.ts',
      [
        'export async function transferPayment(accountId: string) {',
        "  return `payment:${accountId}`;",
        '}',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payment-service.test.ts',
      [
        "import { transferPayment } from './payment-service';",
        '',
        "it('transfers payments', async () => {",
        "  await expect(transferPayment('acct-1')).resolves.toBe('payment:acct-1');",
        '});',
      ].join('\n'),
    );
    commitAll(tempDirectory, 'initial');
    writeWorkspaceFile(
      tempDirectory,
      'src/services/payment-service.ts',
      [
        'export async function transferPayment(accountId: string) {',
        "  return `payment:updated:${accountId}`;",
        '}',
      ].join('\n'),
    );
    commitAll(tempDirectory, 'logic change');

    const result = runCheckCommand({
      cwd: tempDirectory,
      format: 'json',
      baseRef: 'HEAD~1',
      headRef: 'HEAD',
    });

    expect(result.envelope.scope).toEqual({
      mode: 'diff',
      base: 'HEAD~1',
      head: 'HEAD',
      changedFileCount: 1,
    });
    expect(result.envelope.findingCount).toBe(1);
    expect(result.envelope.findings[0].rule.id).toBe(
      'ts.quality.logic-change-without-test-updates',
    );
    expect(result.envelope.findings[0].locations.primary.path).toBe(
      'src/services/payment-service.ts',
    );
  });
});
