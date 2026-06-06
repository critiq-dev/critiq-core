import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { type RequiredCliRuntime } from '../cli.types';
import { installDefaultRulesPackage } from '../test-support/install-default-rules-package';
import {
  buildCatalogInstallCommand,
  detectPackageManager,
} from './detect-package-manager.util';
import { ensureCatalogPackageForCheck } from './ensure-catalog-package.util';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-cli-ensure-'));
}

function createRuntime(
  cwd: string,
  overrides: Partial<RequiredCliRuntime> = {},
): RequiredCliRuntime {
  const stdout: string[] = [];
  const stderr: string[] = [];

  return {
    cwd,
    isInteractive: false,
    writeStdout: (message) => {
      stdout.push(message);
    },
    writeStderr: (message) => {
      stderr.push(message);
    },
    writeRaw: () => undefined,
    ...overrides,
    ...(overrides.writeStdout
      ? {}
      : {
          writeStdout: (message: string) => {
            stdout.push(message);
          },
        }),
    ...(overrides.writeStderr
      ? {}
      : {
          writeStderr: (message: string) => {
            stderr.push(message);
          },
        }),
  };
}

function captureRuntime(
  cwd: string,
  overrides: Partial<RequiredCliRuntime> = {},
): {
  runtime: RequiredCliRuntime;
  stdout: string[];
  stderr: string[];
} {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const runtime = createRuntime(cwd, {
    ...overrides,
    writeStdout: (message) => {
      stdout.push(message);
      overrides.writeStdout?.(message);
    },
    writeStderr: (message) => {
      stderr.push(message);
      overrides.writeStderr?.(message);
    },
  });

  return { runtime, stdout, stderr };
}

describe('ensureCatalogPackageForCheck', () => {
  let tempDirectory = '';

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('returns success when the default catalog is installed in the repository', async () => {
    installDefaultRulesPackage(tempDirectory);

    const { runtime } = captureRuntime(tempDirectory);
    const result = await ensureCatalogPackageForCheck(runtime, 'pretty');

    expect(result.ok).toBe(true);
  });

  it('returns an improved error when the catalog is missing and the session is non-interactive', async () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');

    const { runtime, stderr } = captureRuntime(tempDirectory, {
      cliInstallScope: 'local',
    });
    const result = await ensureCatalogPackageForCheck(runtime, 'pretty');

    expect(result.ok).toBe(false);

    if (result.ok !== false) {
      throw new Error('Expected catalog ensure to fail.');
    }

    expect(result.message).toContain(
      'Critiq could not find the rules catalog package `@critiq/rules`.',
    );
    expect(result.message).toContain(
      'Install in this repository: npm install -D @critiq/rules',
    );
    expect(stderr.join('\n')).toBe('');
  });

  it('uses yarn install commands when yarn.lock is present', async () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');
    writeFileSync(join(tempDirectory, 'yarn.lock'), '# yarn lockfile v1\n', 'utf8');

    const { runtime } = captureRuntime(tempDirectory, {
      cliInstallScope: 'local',
    });
    const result = await ensureCatalogPackageForCheck(runtime, 'json');

    expect(result.ok).toBe(false);

    if (result.ok !== false) {
      throw new Error('Expected catalog ensure to fail.');
    }

    expect(result.message).toContain(
      'Install in this repository: yarn add -D @critiq/rules',
    );
  });

  it('prompts for a local install when the CLI is installed in the repository', async () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');

    const { runtime } = captureRuntime(tempDirectory, {
      cliInstallScope: 'local',
      isInteractive: true,
      promptChoice: jest.fn().mockResolvedValue('local'),
      runPackageInstall: jest.fn().mockImplementation(() => {
        installDefaultRulesPackage(tempDirectory);
        return true;
      }),
    });

    const result = await ensureCatalogPackageForCheck(runtime, 'pretty');

    expect(result.ok).toBe(true);
    expect(runtime.promptChoice).toHaveBeenCalledWith(
      expect.objectContaining({
        options: expect.arrayContaining([
          expect.objectContaining({ id: 'local' }),
          expect.objectContaining({ id: 'cancel' }),
        ]),
      }),
    );
    expect(runtime.runPackageInstall).toHaveBeenCalledWith(
      expect.objectContaining({
        command: expect.objectContaining({
          display: 'npm install -D @critiq/rules',
        }),
      }),
    );
  });

  it('offers repo, global, or cancel when the CLI is installed globally', async () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');

    const { runtime } = captureRuntime(tempDirectory, {
      cliInstallScope: 'global',
      isInteractive: true,
      promptChoice: jest.fn().mockResolvedValue('cancel'),
    });

    const result = await ensureCatalogPackageForCheck(runtime, 'pretty');

    expect(result.ok).toBe(false);

    if (result.ok !== false) {
      throw new Error('Expected catalog ensure to fail.');
    }

    expect(result.message).toContain('Cancelled.');

    expect(runtime.promptChoice).toHaveBeenCalledWith(
      expect.objectContaining({
        options: expect.arrayContaining([
          expect.objectContaining({ id: 'local' }),
          expect.objectContaining({ id: 'global' }),
          expect.objectContaining({ id: 'cancel' }),
        ]),
      }),
    );
  });

  it('skips interactive install for machine-readable output formats', async () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');

    const promptChoice = jest.fn();
    const { runtime } = captureRuntime(tempDirectory, {
      cliInstallScope: 'local',
      isInteractive: true,
      promptChoice,
    });
    const result = await ensureCatalogPackageForCheck(runtime, 'json');

    expect(promptChoice).not.toHaveBeenCalled();
    expect(result.ok).toBe(false);
  });
});

describe('detectPackageManager', () => {
  let tempDirectory = '';

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('detects pnpm from pnpm-lock.yaml', () => {
    writeFileSync(join(tempDirectory, 'package.json'), '{}\n', 'utf8');
    writeFileSync(join(tempDirectory, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n', 'utf8');

    expect(detectPackageManager(tempDirectory)).toBe('pnpm');
    expect(
      buildCatalogInstallCommand('pnpm', '@critiq/rules', 'local').display,
    ).toBe('pnpm add -D @critiq/rules');
  });
});
