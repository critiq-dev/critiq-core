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
  });
});
