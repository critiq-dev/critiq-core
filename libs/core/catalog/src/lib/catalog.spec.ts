import {
  cpSync,
  mkdtempSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  detectRepositoryLanguages,
  filterNormalizedRulesForCatalog,
  loadRuleCatalogText,
  resolveCatalogPackage,
  resolveCatalogRulePaths,
} from '../index';
import type { NormalizedRule } from '@critiq/core-ir';

const validCatalog = [
  'apiVersion: critiq.dev/v1alpha1',
  'kind: RuleCatalog',
  'rules:',
  '  - id: ts.logging.no-console-log',
  '    rulePath: ./rules/no-console.rule.yaml',
  '    presets:',
  '      - recommended',
  '      - strict',
  '  - id: ts.runtime.no-debugger-statement',
  '    rulePath: ./rules/no-debugger.rule.yaml',
  '    presets:',
  '      - strict',
  '  - id: ts.security.no-sql-interpolation',
  '    rulePath: ./rules/ts.security.no-sql-interpolation.rule.yaml',
  '    presets:',
  '      - recommended',
  '      - strict',
  '      - security',
].join('\n');

const typescriptRule: NormalizedRule = {
  apiVersion: 'critiq.dev/v1alpha1',
  kind: 'Rule',
  ruleId: 'ts.logging.no-console-log',
  title: 'Avoid console.log',
  summary: 'Use logger',
  tags: [],
  scope: {
    languages: ['typescript'],
    includeGlobs: [],
    excludeGlobs: [],
    changedLinesOnly: false,
  },
  predicate: { type: 'node', kind: 'CallExpression', where: [] },
  emit: {
    finding: {
      category: 'maintainability',
      severity: 'low',
      confidence: 'high',
      tags: [],
    },
    message: {
      title: { raw: 'Avoid console.log' },
      summary: { raw: 'Use logger' },
    },
  },
  ruleHash: 'hash-1',
};

describe('core catalog', () => {
  let tempDirectory: string;

  beforeEach(() => {
    tempDirectory = mkdtempSync(join(tmpdir(), 'critiq-catalog-'));
    cpSync(
      resolve(
        __dirname,
        '../../../../../apps/cli/src/test-fixtures/default-rules-package',
      ),
      join(tempDirectory, 'node_modules/@critiq/rules'),
      {
        recursive: true,
      },
    );
  });

  afterEach(() => {
    rmSync(tempDirectory, { recursive: true, force: true });
  });

  it('loads valid catalog yaml', () => {
    expect(loadRuleCatalogText(validCatalog, '/tmp/catalog.yaml')).toEqual({
      success: true,
      data: expect.objectContaining({
        kind: 'RuleCatalog',
        rules: expect.arrayContaining([
          expect.objectContaining({
            id: 'ts.logging.no-console-log',
          }),
        ]),
      }),
      path: '/tmp/catalog.yaml',
      uri: 'file:///tmp/catalog.yaml',
    });
  });

  it('resolves rule paths by preset', () => {
    const loaded = loadRuleCatalogText(validCatalog, '/tmp/catalog.yaml');

    if (!loaded.success) {
      throw new Error('Expected catalog load success.');
    }

    expect(resolveCatalogRulePaths(loaded.data, '/pkg', 'recommended')).toEqual([
      {
        id: 'ts.logging.no-console-log',
        rulePath: '/pkg/rules/no-console.rule.yaml',
      },
      {
        id: 'ts.security.no-sql-interpolation',
        rulePath: '/pkg/rules/ts.security.no-sql-interpolation.rule.yaml',
      },
    ]);
    expect(resolveCatalogRulePaths(loaded.data, '/pkg', 'strict')).toHaveLength(3);
    expect(resolveCatalogRulePaths(loaded.data, '/pkg', 'security')).toEqual([
      {
        id: 'ts.security.no-sql-interpolation',
        rulePath: '/pkg/rules/ts.security.no-sql-interpolation.rule.yaml',
      },
    ]);
  });

  it('detects repository languages from supported file extensions', () => {
    expect(
      detectRepositoryLanguages([
        '/repo/src/app.ts',
        '/repo/src/ui.tsx',
        '/repo/src/index.js',
        '/repo/README.md',
      ]),
    ).toEqual(['javascript', 'typescript']);
  });

  it('filters normalized rules by config and detected languages', () => {
    expect(
      filterNormalizedRulesForCatalog(
        [typescriptRule],
        {
          apiVersion: 'critiq.dev/v1alpha1',
          kind: 'CritiqConfig',
          catalogPackage: '@critiq/rules',
          preset: 'recommended',
          disableRules: [],
          disableCategories: [],
          disableLanguages: [],
          ignorePaths: [],
          severityOverrides: {},
        },
        ['typescript'],
      ),
    ).toEqual([typescriptRule]);

    expect(
      filterNormalizedRulesForCatalog(
        [typescriptRule],
        {
          apiVersion: 'critiq.dev/v1alpha1',
          kind: 'CritiqConfig',
          catalogPackage: '@critiq/rules',
          preset: 'recommended',
          disableRules: [],
          disableCategories: ['maintainability'],
          disableLanguages: [],
          ignorePaths: [],
          severityOverrides: {},
        },
        ['typescript'],
      ),
    ).toEqual([]);
  });

  it('treats disabled top-level categories as prefixes', () => {
    const securityRule: NormalizedRule = {
      ...typescriptRule,
      ruleId: 'ts.security.no-sql-interpolation',
      emit: {
        ...typescriptRule.emit,
        finding: {
          ...typescriptRule.emit.finding,
          category: 'security.injection',
        },
      },
    };

    expect(
      filterNormalizedRulesForCatalog(
        [securityRule],
        {
          apiVersion: 'critiq.dev/v1alpha1',
          kind: 'CritiqConfig',
          catalogPackage: '@critiq/rules',
          preset: 'security',
          disableRules: [],
          disableCategories: ['security'],
          disableLanguages: [],
          ignorePaths: [],
          severityOverrides: {},
        },
        ['typescript'],
      ),
    ).toEqual([]);
  });

  it('resolves the default rules package from the workspace', () => {
    const result = resolveCatalogPackage(tempDirectory, '@critiq/rules');

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected package resolution success.');
    }

    expect(result.data.packageRoot).toBe(
      realpathSync(join(tempDirectory, 'node_modules/@critiq/rules')),
    );
    expect(result.data.catalogPath).toContain('catalog.yaml');
  });
});
