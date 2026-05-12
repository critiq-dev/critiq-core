import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

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
});

describe('collectRawSecretMatches', () => {
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
