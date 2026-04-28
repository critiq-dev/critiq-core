import {
  CRITIQ_CONFIG_DEFAULT_PATH,
  loadCritiqConfigForDirectory,
  normalizeCritiqConfig,
  validateCritiqConfig,
} from '../index';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

function createTempWorkspace(): string {
  return mkdtempSync(join(tmpdir(), 'critiq-config-'));
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

describe('core config', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = createTempWorkspace();
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('applies defaults during normalization', () => {
    expect(
      normalizeCritiqConfig({
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'CritiqConfig',
      }),
    ).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'CritiqConfig',
      catalogPackage: undefined,
      preset: 'recommended',
      disableRules: [],
      disableCategories: [],
      disableLanguages: [],
      includeTests: false,
      ignorePaths: [],
      severityOverrides: {},
    });
  });

  it('loads config files from the repo default path', () => {
    writeWorkspaceFile(
      tempDirectory,
      CRITIQ_CONFIG_DEFAULT_PATH,
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: CritiqConfig',
        'preset: strict',
        'disableLanguages:',
        '  - js',
        '  - javascript',
        'ignorePaths:',
        '  - "**/dist/**"',
      ].join('\n'),
    );

    expect(loadCritiqConfigForDirectory(tempDirectory)).toEqual({
      success: true,
      data: {
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'CritiqConfig',
        catalogPackage: undefined,
        preset: 'strict',
        disableRules: [],
        disableCategories: [],
        disableLanguages: ['javascript'],
        includeTests: false,
        ignorePaths: ['**/dist/**'],
        severityOverrides: {},
      },
      path: expect.stringContaining(CRITIQ_CONFIG_DEFAULT_PATH),
      uri: expect.stringContaining(CRITIQ_CONFIG_DEFAULT_PATH),
    });
  });

  it('accepts security preset and hierarchical disabled categories', () => {
    expect(
      normalizeCritiqConfig({
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'CritiqConfig',
        preset: 'security',
        disableCategories: ['security.injection'],
        disableLanguages: ['go', 'python'],
      }),
    ).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'CritiqConfig',
      catalogPackage: undefined,
      preset: 'security',
      disableRules: [],
      disableCategories: ['security.injection'],
      disableLanguages: ['go', 'python'],
      includeTests: false,
      ignorePaths: [],
      severityOverrides: {},
    });
  });

  it('normalizes all supported disableLanguages values', () => {
    expect(
      normalizeCritiqConfig({
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'CritiqConfig',
        disableLanguages: [
          'ts',
          'js',
          'go',
          'python',
          'java',
          'php',
          'ruby',
          'rust',
        ],
      }),
    ).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'CritiqConfig',
      catalogPackage: undefined,
      preset: 'recommended',
      disableRules: [],
      disableCategories: [],
      disableLanguages: [
        'go',
        'java',
        'javascript',
        'php',
        'python',
        'ruby',
        'rust',
        'typescript',
      ],
      includeTests: false,
      ignorePaths: [],
      severityOverrides: {},
    });
  });

  it('accepts explicit test-file inclusion', () => {
    expect(
      normalizeCritiqConfig({
        apiVersion: 'critiq.dev/v1alpha1',
        kind: 'CritiqConfig',
        includeTests: true,
      }),
    ).toEqual({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'CritiqConfig',
      catalogPackage: undefined,
      preset: 'recommended',
      disableRules: [],
      disableCategories: [],
      disableLanguages: [],
      includeTests: true,
      ignorePaths: [],
      severityOverrides: {},
    });
  });

  it('reports validation failures for invalid config content', () => {
    const result = validateCritiqConfig({
      apiVersion: 'critiq.dev/v1alpha1',
      kind: 'CritiqConfig',
      disableLanguages: ['all'],
    });

    expect(result.success).toBe(false);

    if (result.success) {
      throw new Error('Expected validation failure.');
    }

    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'contract.validation.invalid',
          jsonPointer: '/disableLanguages/0',
        }),
      ]),
    );
  });
});
