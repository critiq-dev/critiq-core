import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { CRITIQ_CONFIG_DEFAULT_PATH } from '@critiq/core-config';

import { collectRawSecretMatches } from './detectors';
import { isSecretsEligiblePath } from './eligibility';
import { runSecretsScan } from './run-secrets-scan';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-secrets-scan-'));
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
  runGitCommand(rootDirectory, ['add', '-A']);
  runGitCommand(rootDirectory, ['commit', '-m', message, '--no-gpg-sign']);
}

describe('runSecretsScan', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('detects a fake AWS access key id in a TypeScript file', () => {
    writeWorkspaceFile(
      tempDirectory,
      'src/config.ts',
      "const x = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const result = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: false,
    });

    expect(result.findingCount).toBe(1);
    expect(result.findings[0]?.detectorId).toBe('secrets.aws-access-key-id');
    expect(result.exitCode).toBe(0);
  });

  it('does not set exit code from findings when failOnFindings is false', () => {
    writeWorkspaceFile(
      tempDirectory,
      'keys.txt',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n',
    );

    const result = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: false,
    });

    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    expect(result.exitCode).toBe(0);
  });

  it('sets exit code 1 when findings exist and failOnFindings is true', () => {
    writeWorkspaceFile(
      tempDirectory,
      'keys.txt',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n',
    );

    const result = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: true,
    });

    expect(result.findingCount).toBeGreaterThanOrEqual(1);
    expect(result.exitCode).toBe(1);
  });

  it('scans staged index content when staged option is true', () => {
    initializeGitRepository(tempDirectory);
    writeWorkspaceFile(tempDirectory, 'README.md', 'hello\n');
    commitAll(tempDirectory, 'init');
    writeWorkspaceFile(
      tempDirectory,
      'staged.txt',
      "const k = 'AKIAIOSFODNN7EXAMPLE';\n",
    );
    runGitCommand(tempDirectory, ['add', 'staged.txt']);

    const result = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      staged: true,
      failOnFindings: false,
    });

    expect(result.scope).toEqual({ mode: 'staged', changedFileCount: 1 });
    expect(result.findingCount).toBe(1);
    expect(result.findings[0]?.detectorId).toBe('secrets.aws-access-key-id');
  });

  it('honors secretsScan.disabledDetectors from config', () => {
    writeWorkspaceFile(
      tempDirectory,
      CRITIQ_CONFIG_DEFAULT_PATH,
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: CritiqConfig',
        'secretsScan:',
        '  disabledDetectors:',
        '    - secrets.aws-access-key-id',
      ].join('\n'),
    );
    writeWorkspaceFile(
      tempDirectory,
      'src/config.ts',
      "const x = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const result = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: false,
    });

    expect(result.findingCount).toBe(0);
  });

  it('honors secretsScan.suppressFingerprints from config', () => {
    writeWorkspaceFile(
      tempDirectory,
      'src/config.ts',
      "const x = 'AKIAIOSFODNN7EXAMPLE';\n",
    );

    const first = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: false,
    });

    expect(first.findingCount).toBe(1);

    const fingerprint = first.findings[0]?.fingerprint;

    if (!fingerprint) {
      throw new Error('Expected a secret finding fingerprint.');
    }

    writeWorkspaceFile(
      tempDirectory,
      CRITIQ_CONFIG_DEFAULT_PATH,
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: CritiqConfig',
        'secretsScan:',
        '  suppressFingerprints:',
        `    - ${fingerprint}`,
      ].join('\n'),
    );

    const second = runSecretsScan({
      cwd: tempDirectory,
      target: '.',
      failOnFindings: false,
    });

    expect(second.findingCount).toBe(0);
  });
});

describe('collectRawSecretMatches', () => {
  it('skips detectors listed in disabledDetectors', () => {
    const raw = collectRawSecretMatches("const x = 'AKIAIOSFODNN7EXAMPLE';\n", {
      disabledDetectors: new Set(['secrets.aws-access-key-id']),
    });

    expect(raw.some((m) => m.detectorId === 'secrets.aws-access-key-id')).toBe(
      false,
    );
  });

  it('matches postgres URL with password', () => {
    const raw = collectRawSecretMatches(
      'DATABASE_URL=postgres://admin:hunter2@localhost:5432/db',
    );

    expect(raw.some((m) => m.detectorId === 'secrets.database-url-with-credentials')).toBe(
      true,
    );
  });
});

describe('isSecretsEligiblePath', () => {
  it('allows .env files', () => {
    expect(isSecretsEligiblePath('.env')).toBe(true);
    expect(isSecretsEligiblePath('dir/.env.local')).toBe(true);
  });

  it('rejects png paths', () => {
    expect(isSecretsEligiblePath('assets/logo.png')).toBe(false);
  });
});
