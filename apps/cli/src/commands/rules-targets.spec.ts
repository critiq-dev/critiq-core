import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  resolveSingleFilePath,
  resolveTestTargets,
  resolveValidateTargets,
} from './rules-targets';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-rules-targets-'));
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

describe('rules target resolution', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
    writeWorkspaceFile(tempDirectory, 'rules/example.rule.yaml', 'kind: Rule\n');
    writeWorkspaceFile(tempDirectory, 'rules/example.spec.yaml', 'kind: RuleSpec\n');
    writeWorkspaceFile(
      tempDirectory,
      'node_modules/ignored.rule.yaml',
      'kind: Rule\n',
    );
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('resolves a direct file path for validation', () => {
    const result = resolveValidateTargets(tempDirectory, 'rules/example.rule.yaml');

    expect(result).toEqual({
      success: true,
      files: [join(tempDirectory, 'rules/example.rule.yaml')],
    });
  });

  it('resolves glob matches while skipping node_modules', () => {
    const result = resolveValidateTargets(tempDirectory, 'rules/*.rule.yaml');

    expect(result).toEqual({
      success: true,
      files: [join(tempDirectory, 'rules/example.rule.yaml')],
    });
  });

  it('reports invalid validate targets', () => {
    const result = resolveValidateTargets(tempDirectory, 'rules/missing.rule.yaml');

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected target resolution failure.');
    }

    const failure = result as Extract<typeof result, { success: false }>;

    expect(failure.diagnostics).toEqual([
      expect.objectContaining({
        code: 'cli.input.invalid',
        message: 'No files matched `rules/missing.rule.yaml`.',
      }),
    ]);
  });

  it('defaults test targets to spec globs', () => {
    const result = resolveTestTargets(tempDirectory, undefined);

    expect(result).toEqual({
      success: true,
      target: '**/*.spec.yaml',
      files: [join(tempDirectory, 'rules/example.spec.yaml')],
    });
  });

  it('rejects glob input for single-file commands', () => {
    const result = resolveSingleFilePath(tempDirectory, 'rules/*.rule.yaml');

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected single-file failure.');
    }

    const failure = result as Extract<typeof result, { success: false }>;

    expect(failure.diagnostics).toEqual([
      expect.objectContaining({
        code: 'cli.input.invalid',
        message:
          'Expected a concrete file path for `rules/*.rule.yaml`, not a glob.',
      }),
    ]);
  });
});
