import type { AnalyzedFile } from '@critiq/core-rules-engine';
import { analyzeTypeScriptFile } from '@critiq/adapter-typescript';

import {
  createFileContexts,
  isBatchAlternative,
  isFixtureLikePath,
  isTestPath,
  matchingTestPathsForSource,
  normalizeEndpointPath,
  normalizeStem,
} from './context';

function analyze(path: string, text: string): AnalyzedFile {
  const result = analyzeTypeScriptFile(path, text);

  if (!result.success) {
    throw new Error(
      `Expected TypeScript analysis to succeed for ${path}: ${JSON.stringify(
        result.diagnostics,
      )}`,
    );
  }

  return result.data;
}

describe('project analysis context helpers', () => {
  it('matches sibling and index-based test paths', () => {
    expect(matchingTestPathsForSource('src/services/payment-service.ts')).toEqual(
      expect.arrayContaining([
        'src/services/payment-service.spec.ts',
        'src/services/payment-service.test.ts',
        'src/services/__tests__/payment-service.spec.ts',
      ]),
    );
    expect(matchingTestPathsForSource('src/services/refund/index.ts')).toEqual(
      expect.arrayContaining([
        'src/services/refund.spec.ts',
        'src/services/refund.test.ts',
        'src/services/__tests__/refund.spec.ts',
      ]),
    );
    expect(normalizeStem('src/services/refund/index.ts')).toBe('refund');
    expect(normalizeStem('src/services/__tests__/refund/index.test.ts')).toBe(
      'refund',
    );
  });

  it('normalizes endpoint paths and recognizes test and fixture paths', () => {
    expect(normalizeEndpointPath('https://api.example.com/staff/users/')).toBe(
      '/staff/users',
    );
    expect(normalizeEndpointPath('/staff/users///')).toBe('/staff/users');
    expect(normalizeEndpointPath('')).toBe('/');
    expect(isTestPath('src/lib/example.spec.ts')).toBe(true);
    expect(isTestPath('src/lib/example.ts')).toBe(false);
    expect(isFixtureLikePath('src/services/__fixtures__/payment.ts')).toBe(
      true,
    );
    expect(isFixtureLikePath('src/services/payment.ts')).toBe(false);
  });

  it('creates file contexts with import resolution, routes, frontend calls, and guard detection', () => {
    const files = [
      analyze(
        'src/auth/guards.ts',
        [
          'export function authorize(user: unknown) {',
          '  return Boolean(user);',
          '}',
          '',
          'export function verifyOwnership(ownerId: string) {',
          '  return ownerId.length > 0;',
          '}',
        ].join('\n'),
      ),
      analyze(
        'src/api/staff.ts',
        [
          "import { authorize, verifyOwnership } from '../auth/guards';",
          '',
          'const router = {',
          '  get: (_path: string, handler: unknown) => handler,',
          '};',
          '',
          "router.get('/staff/users/', async (req) => {",
          '  authorize(req.user);',
          '  verifyOwnership(req.params.userId);',
          '  return deleteUser(req.params.userId);',
          '});',
        ].join('\n'),
      ),
      analyze(
        'src/frontend/staff.tsx',
        [
          'const session = {',
          "  user: { id: 'employee-1' },",
          '};',
          '',
          'export async function loadStaffDirectory() {',
          '  if (!session.user) {',
          '    return [];',
          '  }',
          '',
          "  return fetch('https://api.example.com/staff/users/');",
          '}',
        ].join('\n'),
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
      ),
    ];

    const contexts = createFileContexts(files);
    const backendContext = contexts.get('src/api/staff.ts');
    const frontendContext = contexts.get('src/frontend/staff.tsx');
    const testContext = contexts.get('src/services/payment-service.test.ts');

    expect(backendContext).toBeDefined();
    expect(frontendContext).toBeDefined();
    expect(testContext).toBeDefined();

    if (!backendContext || !frontendContext || !testContext) {
      throw new Error('Expected file contexts to be created for every file.');
    }

    expect(backendContext.imports).toEqual([
      expect.objectContaining({
        source: '../auth/guards',
        resolvedPath: 'src/auth/guards.ts',
      }),
    ]);
    expect(backendContext.routes).toEqual([
      expect.objectContaining({
        path: '/staff/users',
      }),
    ]);
    expect(backendContext.hasAuthGuard).toBe(true);
    expect(backendContext.hasOwnershipGuard).toBe(true);
    expect(frontendContext.frontendCalls).toEqual([
      expect.objectContaining({
        path: '/staff/users',
      }),
    ]);
    expect(frontendContext.hasAuthGuard).toBe(true);
    expect(testContext.isTestFile).toBe(true);
  });

  it('recognizes viable batch alternatives without treating identical names as batches', () => {
    expect(isBatchAlternative('loadUsersBatch', 'loadUser')).toBe(true);
    expect(isBatchAlternative('loadUsers', 'loadUser')).toBe(true);
    expect(isBatchAlternative('loadUser', 'loadUser')).toBe(false);
  });
});
