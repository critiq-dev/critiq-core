import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { runCli } from './main';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-cli-'));
}

function writeRuleFile(
  rootDirectory: string,
  relativePath: string,
  content: string,
): void {
  mkdirSync(dirname(join(rootDirectory, relativePath)), { recursive: true });
  writeFileSync(join(rootDirectory, relativePath), content, 'utf8');
}

function writeCritiqConfig(
  rootDirectory: string,
  bodyLines: string[] = [],
): void {
  writeRuleFile(
    rootDirectory,
    '.critiq/config.yaml',
    [
      'apiVersion: critiq.dev/v1alpha1',
      'kind: CritiqConfig',
      ...bodyLines,
    ].join('\n'),
  );
}

function installDefaultRulesPackage(rootDirectory: string): void {
  cpSync(
    resolve(__dirname, 'test-fixtures/default-rules-package'),
    join(rootDirectory, 'node_modules/@critiq/rules'),
    {
      recursive: true,
    },
  );
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

function sanitizeOutput(value: string, tempDirectory: string): string {
  const escaped = tempDirectory.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ansiColorPattern = new RegExp(
    `${String.fromCharCode(27)}\\[[0-9;]*m`,
    'g',
  );

  return value
    .replace(ansiColorPattern, '')
    .replace(new RegExp(escaped, 'g'), '<TMP>')
    .replace(/file:\/\/\/<TMP>/g, 'file://<TMP>');
}

function runCommand(args: readonly string[], cwd: string) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const exitCode = runCli(args, {
    cwd,
    writeStdout: (message) => {
      stdout.push(message);
    },
    writeStderr: (message) => {
      stderr.push(message);
    },
  });

  return {
    exitCode,
    stdout: stdout.join('\n'),
    stderr: stderr.join('\n'),
  };
}

const validRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: ts.logging.no-console-log',
  '  title: Avoid console.log in production code',
  '  summary: Production code must use the structured logger.',
  'scope:',
  '  languages:',
  '    - typescript',
  'match:',
  '  node:',
  '    kind: CallExpression',
  '    bind: call',
  'emit:',
  '  finding:',
  '    category: maintainability',
  '    severity: low',
  '    confidence: high',
  '  message:',
  '    title: Avoid `${captures.call.text}`',
  '    summary: Use `${rule.title}` in `${file.path}`',
  '    detail: File language `${file.language}`',
  '  remediation:',
  '    summary: Replace `${captures.call.text}`',
].join('\n');

const invalidRule = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: Rule',
  'metadata:',
  '  id: bad id',
  '  title: Invalid rule',
  '  summary: Broken rule',
  'scope:',
  '  languages: []',
  'match:',
  '  any: []',
  'emit:',
  '  finding:',
  '    category: maintainability',
  '    severity: low',
  '    confidence: high',
  '  message:',
  '    title: " "',
  '    summary: "${captures.missing.text}"',
].join('\n');

const validRuleSpec = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: RuleSpec',
  'rulePath: ./valid.rule.yaml',
  'fixtures:',
  '  - name: console log is flagged',
  '    sourcePath: ./invalid.ts',
  '    expect:',
  '      findingCount: 1',
  '      allRuleIds:',
  '        - ts.logging.no-console-log',
  '      allSeverities:',
  '        - low',
].join('\n');

describe('cli', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
    installDefaultRulesPackage(tempDirectory);
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('prints stable help for the default command', () => {
    const result = runCommand([], tempDirectory);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('critiq CLI');
    expect(result.stdout).toContain('critiq check [target]');
    expect(result.stdout).toContain('critiq audit secrets [target]');
    expect(result.stdout).toContain('critiq audit [--help]');
    expect(result.stdout).toContain('critiq rules validate <glob>');
    expect(result.stdout).toContain('critiq rules test [glob]');
  });

  it('returns a non-zero exit code for an invalid subcommand', () => {
    const result = runCommand(['unknown'], tempDirectory);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe('Unknown command: unknown');
  });

  it('prints audit help for critiq audit with no subcommand', () => {
    const result = runCommand(['audit'], tempDirectory);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('critiq audit');
    expect(result.stdout).toContain('critiq audit secrets');
  });

  it('prints audit help for critiq audit --help', () => {
    const result = runCommand(['audit', '--help'], tempDirectory);

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('critiq audit secrets');
  });

  it('returns a non-zero exit for unknown audit subcommand', () => {
    const result = runCommand(['audit', 'nope'], tempDirectory);

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Unknown command: audit nope');
  });

  it('audit secrets detects a dummy AWS key and exits non-zero', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(
      tempDirectory,
      'src/leak.ts',
      "export const k = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const result = runCommand(['audit', 'secrets', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const payload = JSON.parse(result.stdout) as {
      command: string;
      format: string;
      target: string;
      findingCount: number;
    };

    expect(payload.command).toBe('audit-secrets');
    expect(payload.format).toBe('json');
    expect(payload.target).toBe('.');
    expect(payload.findingCount).toBeGreaterThanOrEqual(1);
  });

  it('checks a repository and returns zero findings for clean files', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/valid.ts', 'export const value = 1;\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(0);
    const envelope = JSON.parse(result.stdout) as {
      command: string;
      catalogPackage: string;
      preset: string;
      scope: { mode: string };
      scannedFileCount: number;
      matchedRuleCount: number;
      findingCount: number;
      findings: unknown[];
      ruleSummaries: unknown[];
      diagnostics: unknown[];
      secretsScan?: {
        findingCount: number;
        scannedFileCount: number;
        findings: unknown[];
      };
    };

    expect(envelope.command).toBe('check');
    expect(envelope.catalogPackage).toBe('@critiq/rules');
    expect(envelope.preset).toBe('recommended');
    expect(envelope.scope).toEqual({ mode: 'repo' });
    expect(envelope.scannedFileCount).toBe(1);
    expect(envelope.matchedRuleCount).toBe(40);
    expect(envelope.findingCount).toBe(0);
    expect(envelope.findings).toEqual([]);
    expect(envelope.ruleSummaries).toEqual([]);
    expect(envelope.diagnostics).toEqual([]);
    expect(envelope.secretsScan).toMatchObject({
      findingCount: 0,
      scannedFileCount: expect.any(Number),
    });
    expect(envelope.secretsScan?.findings).toEqual([]);
  });

  it('emits findings for repository checks with stable json output', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(result.stdout) as {
      command: string;
      provenance: {
        engineKind: string;
        engineVersion: string;
        generatedAt: string;
      };
      findingCount: number;
      findings: Array<{
        rule: { id: string };
        severity: string;
        locations: { primary: { path: string; startLine: number } };
        fingerprints: { primary: string };
        attributes?: { detail?: string };
        provenance?: unknown;
      }>;
      ruleSummaries: Array<{
        ruleId: string;
        findingCount: number;
        severityCounts: {
          low: number;
          medium: number;
          high: number;
          critical: number;
        };
      }>;
    };

    expect(envelope.command).toBe('check');
    expect(envelope.provenance.engineKind).toBe('critiq-cli');
    expect(envelope.provenance.engineVersion).toBe('0.0.1');
    expect(typeof envelope.provenance.generatedAt).toBe('string');
    expect(envelope.findingCount).toBe(1);
    expect(envelope.findings[0].rule.id).toBe('ts.logging.no-console-log');
    expect(envelope.findings[0].severity).toBe('low');
    expect(envelope.findings[0].locations.primary.path).toBe('src/invalid.ts');
    expect(envelope.findings[0].locations.primary.startLine).toBe(1);
    expect(envelope.findings[0].fingerprints).toEqual({
      primary: expect.any(String),
    });
    expect(envelope.findings[0].attributes).toBeUndefined();
    expect(envelope.findings[0]).not.toHaveProperty('provenance');
    expect(envelope.ruleSummaries).toEqual([
      {
        ruleId: 'ts.logging.no-console-log',
        findingCount: 1,
        severityCounts: {
          low: 1,
          medium: 0,
          high: 0,
          critical: 0,
        },
      },
    ]);
  });

  it('renders pretty check output like a test runner failure report', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check'], tempDirectory);
    const output = sanitizeOutput(result.stdout, tempDirectory);

    expect(result.exitCode).toBe(1);
    expect(output).toContain('Rule Results');
    expect(output).toContain('✓ No Debugger Statement');
    expect(output).toContain('✓ No Console Error');
    expect(output).toContain('✕ No Console Log');
    expect(output).toContain('✓ No Dynamic Execution');
    expect(output).toContain('✓ No Request Path File Read');
    expect(output).toContain('✓ No Sql Interpolation');
    expect(output).toContain('Rule Results');
    expect(output).toContain('● src/invalid.ts');
    expect(output).toContain(
      'Use the project logger instead of `console.log("hello")`.',
    );
    expect(output).toContain('> 1 | console.log("hello");');
    expect(output).toContain('| ^^^^^^^^^^^^^^^^^^^^');
    expect(output).toContain('at src/invalid.ts:1:1');
    expect(output).toContain('Checked 1 file(s) against 40 rule(s)');
    expect(output).toContain('Rules:       1 failed, 39 passed, 40 total');
    expect(output).toContain('Files:       1 failed, 0 passed, 1 total');
    expect(output).toContain('Findings:    1 total');
  });

  it('exports check findings as SARIF', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check', '.', '--format=sarif'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const sarif = JSON.parse(result.stdout) as {
      version: string;
      runs: Array<{
        tool: { driver: { name: string } };
        results: Array<{ ruleId: string; partialFingerprints?: { primary?: string } }>;
      }>;
    };

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.tool.driver.name).toBe('critiq-cli');
    expect(sarif.runs[0]?.results[0]?.ruleId).toBe('ts.logging.no-console-log');
    expect(sarif.runs[0]?.results[0]?.partialFingerprints?.primary).toEqual(
      expect.any(String),
    );
  });

  it('exports check findings as HTML', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check', '.', '--format=html'], tempDirectory);

    expect(result.exitCode).toBe(1);
    expect(result.stdout).toContain('<!doctype html>');
    expect(result.stdout).toContain('<h1>Critiq Check Report</h1>');
    expect(result.stdout).toContain('ts.logging.no-console-log');
    expect(result.stdout).toContain('src/invalid.ts:1:1');
  });

  it('defaults to the public rules catalog when config omits catalog.package', () => {
    writeCritiqConfig(tempDirectory, ['preset: recommended']);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(result.stdout) as {
      catalogPackage: string;
      matchedRuleCount: number;
      findingCount: number;
    };

    expect(envelope.catalogPackage).toBe('@critiq/rules');
    expect(envelope.matchedRuleCount).toBe(40);
    expect(envelope.findingCount).toBe(1);
  });

  it('uses default settings when the repo config is missing', () => {
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(result.stdout) as {
      catalogPackage: string;
      preset: string;
      scannedFileCount: number;
      matchedRuleCount: number;
      findingCount: number;
      diagnostics: Array<{ code: string }>;
    };

    expect(envelope.catalogPackage).toBe('@critiq/rules');
    expect(envelope.preset).toBe('recommended');
    expect(envelope.scannedFileCount).toBe(1);
    expect(envelope.matchedRuleCount).toBe(40);
    expect(envelope.findingCount).toBe(1);
    expect(envelope.diagnostics).toEqual([]);
  });

  it('ignores unit test files by default', () => {
    writeRuleFile(
      tempDirectory,
      'src/invalid.test.ts',
      'console.log("hello from test");\n',
    );

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);
    const envelope = JSON.parse(result.stdout) as {
      scannedFileCount: number;
      findingCount: number;
      diagnostics: Array<{ code: string }>;
    };

    expect(result.exitCode).toBe(0);
    expect(envelope.scannedFileCount).toBe(0);
    expect(envelope.findingCount).toBe(0);
    expect(envelope.diagnostics).toEqual([
      expect.objectContaining({
        code: 'catalog.repo.no-supported-languages',
      }),
    ]);
  });

  it('includes unit test files when config opts in', () => {
    writeCritiqConfig(tempDirectory, ['includeTests: true']);
    writeRuleFile(
      tempDirectory,
      'src/invalid.test.ts',
      'console.log("hello from test");\n',
    );

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);
    const envelope = JSON.parse(result.stdout) as {
      scannedFileCount: number;
      findingCount: number;
    };

    expect(result.exitCode).toBe(1);
    expect(envelope.scannedFileCount).toBe(1);
    expect(envelope.findingCount).toBe(1);
  });

  it('returns an error when diff mode is used outside a git repository', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const result = runCommand(
      ['check', '.', '--base', 'HEAD~1', '--head', 'HEAD'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain(
      'Diff mode requires the target path to be inside a git repository.',
    );
  });

  it('checks only changed supported files in diff mode', () => {
    initializeGitRepository(tempDirectory);
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/changed.ts', 'export const value = 1;\n');
    writeRuleFile(tempDirectory, 'src/unchanged.ts', 'console.log("old");\n');
    commitAll(tempDirectory, 'initial');
    writeRuleFile(tempDirectory, 'src/changed.ts', 'console.log("new");\n');
    commitAll(tempDirectory, 'change source');

    const result = runCommand(
      ['check', '.', '--base', 'HEAD~1', '--head', 'HEAD', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(result.stdout) as {
      scope: { mode: string; changedFileCount: number };
      scannedFileCount: number;
      findings: Array<{ locations: { primary: { path: string } } }>;
    };

    expect(envelope.scope.mode).toBe('diff');
    expect(envelope.scope.changedFileCount).toBe(1);
    expect(envelope.scannedFileCount).toBe(1);
    expect(
      envelope.findings.map((finding) => finding.locations.primary.path),
    ).toEqual(['src/changed.ts']);
  });

  it('returns success when a diff contains no changed supported files', () => {
    initializeGitRepository(tempDirectory);
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'README.md', '# readme\n');
    commitAll(tempDirectory, 'initial');
    writeRuleFile(tempDirectory, 'README.md', '# updated readme\n');
    commitAll(tempDirectory, 'docs');

    const result = runCommand(
      ['check', '.', '--base', 'HEAD~1', '--head', 'HEAD', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(0);
    const envelope = JSON.parse(result.stdout) as {
      scope: { mode: string; changedFileCount: number };
      scannedFileCount: number;
      findingCount: number;
    };

    expect(envelope.scope.mode).toBe('diff');
    expect(envelope.scope.changedFileCount).toBe(0);
    expect(envelope.scannedFileCount).toBe(0);
    expect(envelope.findingCount).toBe(0);
  });

  it('uses strict preset to activate strict-only rules', () => {
    writeCritiqConfig(tempDirectory, ['preset: strict']);
    writeRuleFile(
      tempDirectory,
      'src/core/random.ts',
      'export const value = Math.random();\n',
    );

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(result.stdout) as {
      matchedRuleCount: number;
      findingCount: number;
      findings: Array<{
        rule: { id: string };
        locations: { primary: { path: string } };
      }>;
    };

    expect(envelope.matchedRuleCount).toBe(58);
    expect(envelope.findingCount).toBe(1);
    expect(envelope.findings[0].rule.id).toBe(
      'ts.random.no-math-random-in-core',
    );
    expect(envelope.findings[0].locations.primary.path).toBe(
      'src/core/random.ts',
    );
  });

  it('applies severity overrides without changing finding fingerprints', () => {
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    writeCritiqConfig(tempDirectory);
    const baseline = JSON.parse(
      runCommand(['check', '.', '--format=json'], tempDirectory).stdout,
    ) as {
      findings: Array<{ severity: string; fingerprints: { primary: string } }>;
    };

    writeCritiqConfig(tempDirectory, [
      'severityOverrides:',
      '  ts.logging.no-console-log: high',
    ]);
    const overridden = JSON.parse(
      runCommand(['check', '.', '--format=json'], tempDirectory).stdout,
    ) as {
      findings: Array<{ severity: string; fingerprints: { primary: string } }>;
    };

    expect(baseline.findings[0].severity).toBe('low');
    expect(overridden.findings[0].severity).toBe('high');
    expect(overridden.findings[0].fingerprints.primary).toBe(
      baseline.findings[0].fingerprints.primary,
    );
  });

  it('supports disableCategories and ignorePaths in config', () => {
    writeCritiqConfig(tempDirectory, [
      'disableCategories:',
      '  - maintainability',
      'ignorePaths:',
      '  - "**/ignored/**"',
    ]);
    writeRuleFile(tempDirectory, 'src/ignored/file.ts', 'console.log("x");\n');
    writeRuleFile(tempDirectory, 'src/live.ts', 'console.log("y");\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);
    const envelope = JSON.parse(result.stdout) as {
      findingCount: number;
      matchedRuleCount: number;
    };

    expect(result.exitCode).toBe(0);
    expect(envelope.matchedRuleCount).toBe(37);
    expect(envelope.findingCount).toBe(0);
  });

  it('truncates multiline function frames in pretty output', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(
      tempDirectory,
      'node_modules/@critiq/rules/catalog.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: RuleCatalog',
        'rules:',
        '  - id: ts.quality.function-frame-truncation',
        '    rulePath: ./rules/ts.quality.function-frame-truncation.rule.yaml',
        '    presets:',
        '      - recommended',
      ].join('\n'),
    );
    writeRuleFile(
      tempDirectory,
      'node_modules/@critiq/rules/rules/ts.quality.function-frame-truncation.rule.yaml',
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.quality.function-frame-truncation',
        '  title: Truncate function frames',
        '  summary: Multi-line function matches should not dump the whole function.',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: FunctionDeclaration',
        '    bind: fn',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Review function body',
        '    summary: Keep the frame compact.',
        '  remediation:',
        '    summary: Trim the rendered frame.',
      ].join('\n'),
    );
    writeRuleFile(
      tempDirectory,
      'src/invalid.ts',
      [
        'export function example() {',
        '  const first = 1;',
        '  const second = 2;',
        '  const third = 3;',
        '  return first + second + third;',
        '}',
      ].join('\n'),
    );

    const result = runCommand(['check'], tempDirectory);
    const output = sanitizeOutput(result.stdout, tempDirectory);

    expect(result.exitCode).toBe(1);
    expect(output).toContain('more line(s) omitted');
    expect(output).not.toContain('return first + second + third;');
  });

  it('renders an interactive scan banner and progress updates', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'src/invalid.ts', 'console.log("hello");\n');

    const stdout: string[] = [];
    const stderr: string[] = [];
    const raw: string[] = [];

    const exitCode = runCli(['check'], {
      cwd: tempDirectory,
      isInteractive: true,
      writeStdout: (message) => {
        stdout.push(message);
      },
      writeStderr: (message) => {
        stderr.push(message);
      },
      writeRaw: (message) => {
        raw.push(message);
      },
    });

    expect(exitCode).toBe(1);
    expect(stderr).toEqual([]);
    expect(stdout.join('\n')).toContain('Rule Results');
    expect(raw.join('')).toContain('Critiq Scan');
    expect(raw.join('')).toContain('Progress: [');
    expect(raw.join('')).toContain('Scanning files');
  });

  it('returns success with an info diagnostic when no supported languages are detected', () => {
    writeCritiqConfig(tempDirectory);
    writeRuleFile(tempDirectory, 'README.md', '# docs\n');

    const result = runCommand(['check', '.', '--format=json'], tempDirectory);
    const envelope = JSON.parse(result.stdout) as {
      exitCode: number;
      diagnostics: Array<{ code: string; severity: string }>;
    };

    expect(result.exitCode).toBe(0);
    expect(envelope.exitCode).toBe(0);
    expect(envelope.diagnostics).toEqual([
      expect.objectContaining({
        code: 'catalog.repo.no-supported-languages',
        severity: 'info',
      }),
    ]);
  });

  it('rejects SARIF format for audit secrets', () => {
    const result = runCommand(
      ['audit', 'secrets', '.', '--format=sarif'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Expected `--format` to be `pretty` or `json`');
  });

  it('rejects legacy rules-glob check usage with a migration error', () => {
    writeCritiqConfig(tempDirectory);

    const result = runCommand(
      ['check', 'rules/*.rule.yaml', '.', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain(
      'The `check` command no longer accepts a rules glob.',
    );
  });

  it('renders pretty validate output for multiple files', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);
    writeRuleFile(tempDirectory, 'invalid.rule.yaml', invalidRule);

    const result = runCommand(
      ['rules', 'validate', '*.rule.yaml'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(sanitizeOutput(result.stdout, tempDirectory)).toMatchInlineSnapshot(`
"Validated 2 file(s) for \`*.rule.yaml\`

invalid.rule.yaml
ERROR [semantic.rule-id.invalid] Rule metadata.id must use either a dotted slug such as \`ts.logging.no-console-log\` or an OSS catalog code such as \`CRQ-SEC-016\`.
  Location: file://<TMP>/invalid.rule.yaml:4:7
  Pointer: /metadata/id
  Details: {
    "received": "bad id"
  }

ERROR [semantic.scope.languages.empty] Rule scope.languages must contain at least one language.
  Location: file://<TMP>/invalid.rule.yaml:8:14
  Pointer: /scope/languages

ERROR [semantic.logical.empty-any] Logical \`any\` groups must contain at least one child condition.
  Location: file://<TMP>/invalid.rule.yaml:10:8
  Pointer: /match/any

ERROR [semantic.capture.unreachable-reference] Template variable \`\${captures.missing.text}\` references capture \`missing\`, which is not reachable from this rule condition.
  Location: file://<TMP>/invalid.rule.yaml:18:14
  Pointer: /emit/message/summary
  Details: {
    "expression": "captures.missing.text",
    "capture": "missing"
  }

valid.rule.yaml
OK

Exit code: 1"
`);
  });

  it('renders json validate output with a stable envelope', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);
    writeRuleFile(tempDirectory, 'invalid.rule.yaml', invalidRule);

    const result = runCommand(
      ['rules', 'validate', '*.rule.yaml', '--format', 'json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    const envelope = JSON.parse(
      sanitizeOutput(result.stdout, tempDirectory),
    ) as {
      command: string;
      matchedFileCount: number;
      results: Array<{
        path: string;
        success: boolean;
        diagnostics: unknown[];
      }>;
      diagnostics: Array<{ code: string }>;
      exitCode: number;
    };

    expect(envelope.command).toBe('rules.validate');
    expect(envelope.matchedFileCount).toBe(2);
    expect(envelope.exitCode).toBe(1);
    expect(envelope.results.map((result) => result.path)).toEqual([
      'invalid.rule.yaml',
      'valid.rule.yaml',
    ]);
    expect(envelope.results[0].diagnostics).toHaveLength(4);
    expect(envelope.diagnostics.map((diagnostic) => diagnostic.code)).toEqual([
      'semantic.rule-id.invalid',
      'semantic.scope.languages.empty',
      'semantic.logical.empty-any',
      'semantic.capture.unreachable-reference',
    ]);
  });

  it('renders pretty normalize output', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);

    const result = runCommand(
      ['rules', 'normalize', 'valid.rule.yaml'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(0);
    const output = sanitizeOutput(result.stdout, tempDirectory)
      .split('${')
      .join('$<');

    expect(output).toContain('Parsed Summary');
    expect(output).toContain('Normalization: success');
    expect(output).toContain('"ruleId": "ts.logging.no-console-log"');
    expect(output).toContain('"raw": "Avoid `$<captures.call.text}`"');
    expect(output).toContain(
      '"ruleHash": "caf39ee108746bb25e8a8cfccc8cfee70a0e161e44ef5ebd8617ce8f9f37cd47"',
    );
  });

  it('renders json explain output', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);

    const result = runCommand(
      ['rules', 'explain', 'valid.rule.yaml', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(0);
    const envelope = JSON.parse(
      sanitizeOutput(result.stdout, tempDirectory),
    ) as {
      command: string;
      exitCode: number;
      ruleHash: string;
      parsedSummary: { phases: { normalization: string }; ruleId: string };
      semanticStatus: { success: boolean; diagnostics: unknown[] };
      templateVariables: Record<string, Array<{ expression: string }>>;
    };

    expect(envelope.command).toBe('rules.explain');
    expect(envelope.exitCode).toBe(0);
    expect(envelope.ruleHash).toBe(
      'caf39ee108746bb25e8a8cfccc8cfee70a0e161e44ef5ebd8617ce8f9f37cd47',
    );
    expect(envelope.parsedSummary.ruleId).toBe('ts.logging.no-console-log');
    expect(envelope.parsedSummary.phases.normalization).toBe('success');
    expect(envelope.semanticStatus).toEqual({
      success: true,
      diagnostics: [],
    });
    expect(
      envelope.templateVariables['emit.message.summary'].map(
        (reference) => reference.expression,
      ),
    ).toEqual(['rule.title', 'file.path']);
  });

  it('runs rule specs in pretty mode', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);
    writeRuleFile(tempDirectory, 'valid.spec.yaml', validRuleSpec);
    writeRuleFile(tempDirectory, 'invalid.ts', 'console.log("hello");\n');

    const result = runCommand(['rules', 'test'], tempDirectory);

    expect(result.exitCode).toBe(0);
    expect(sanitizeOutput(result.stdout, tempDirectory)).toContain(
      'PASS console log is flagged (source)',
    );
    expect(sanitizeOutput(result.stdout, tempDirectory)).toContain(
      'Tested 1 spec file(s) for `**/*.spec.yaml`',
    );
  });

  it('renders json test output with a stable envelope', () => {
    writeRuleFile(tempDirectory, 'valid.rule.yaml', validRule);
    writeRuleFile(tempDirectory, 'valid.spec.yaml', validRuleSpec);
    writeRuleFile(tempDirectory, 'invalid.ts', 'console.log("hello");\n');

    const result = runCommand(
      ['rules', 'test', '*.spec.yaml', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(0);
    const envelope = JSON.parse(result.stdout) as {
      command: string;
      matchedFileCount: number;
      exitCode: number;
      results: Array<{
        specPath: string;
        success: boolean;
        result: {
          fixtureResults: Array<{
            name: string;
            success: boolean;
            emittedFindings: unknown[];
          }>;
        };
      }>;
    };

    expect(envelope.command).toBe('rules.test');
    expect(envelope.matchedFileCount).toBe(1);
    expect(envelope.exitCode).toBe(0);
    expect(envelope.results[0].specPath).toBe('valid.spec.yaml');
    expect(envelope.results[0].success).toBe(true);
    expect(envelope.results[0].result.fixtureResults[0].name).toBe(
      'console log is flagged',
    );
  });

  it('returns exit code 1 when a glob matches no files', () => {
    const result = runCommand(
      ['rules', 'validate', '*.missing.yaml'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('No files matched');
  });

  it('returns exit code 2 for unreadable normalize paths', () => {
    const result = runCommand(
      ['rules', 'normalize', 'missing.rule.yaml', '--format=json'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain('"exitCode": 2');
    expect(result.stdout).toContain('runtime.internal.error');
  });

  it('rejects globs for explain', () => {
    const result = runCommand(
      ['rules', 'explain', '*.rule.yaml'],
      tempDirectory,
    );

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Expected a concrete file path');
  });
});
