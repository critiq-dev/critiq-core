import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptAsyncCorrectnessFacts } from './typescript-async-correctness';

function analyze(text: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectTypescriptAsyncCorrectnessFacts({
    nodeIds: new WeakMap(),
    path: 'src/async-correctness-sample.ts',
    program,
    sourceText: text,
  });
}

describe('collectTypescriptAsyncCorrectnessFacts', () => {
  it('emits async correctness facts for common failure patterns', () => {
    const facts = analyze(
      [
        'async function loadProfile(): Promise<{ id: number }> {',
        '  return { id: 1 };',
        '}',
        '',
        'export function renderProfile(): void {',
        '  loadProfile();',
        '}',
        '',
        'export async function redundantAwait(): Promise<number> {',
        '  return await loadProfile().then((p) => p.id);',
        '}',
        '',
        'export async function invalidAwait(): Promise<void> {',
        '  await 1;',
        '  await Math.max(1, 2);',
        '}',
        '',
        'export function promiseHandler(): void {',
        '  loadProfile().then(() => {',
        '    await loadProfile();',
        '  });',
        '}',
        '',
        'export function misused(): void {',
        '  [1, 2].map(async (value) => value + 1);',
        '}',
        '',
        'export function spin(): never {',
        '  while (true) {',
        '    console.log("tick");',
        '  }',
        '}',
        '',
        'export function spinFor(): never {',
        '  for (;;) {',
        '    console.log("tick");',
        '  }',
        '}',
      ].join('\n'),
    );

    const kinds = facts.map((fact) => fact.kind).sort();

    expect(kinds).toEqual(
      expect.arrayContaining([
        'async.floating-promise-in-function',
        'async.infinite-loop',
        'async.invalid-await-expression',
        'async.misused-promises',
        'async.missing-async-on-promise-method',
        'async.unnecessary-return-await',
      ]),
    );
  });

  it('ignores handled promises and loops with exits', () => {
    const facts = analyze(
      [
        'async function loadProfile(): Promise<{ id: number }> {',
        '  return { id: 1 };',
        '}',
        '',
        'export async function handled(): Promise<void> {',
        '  await loadProfile();',
        '  void loadProfile();',
        '  return loadProfile();',
        '}',
        '',
        'export function loopWithBreak(): void {',
        '  while (true) {',
        '    if (Math.random() > 0.5) {',
        '      break;',
        '    }',
        '  }',
        '}',
        '',
        'export async function tryReturnAwait(): Promise<number> {',
        '  try {',
        '    return await loadProfile().then((p) => p.id);',
        '  } catch {',
        '    return 0;',
        '  }',
        '}',
        '',
        'export function asyncHandler(): void {',
        '  loadProfile().then(async () => {',
        '    await loadProfile();',
        '  });',
        '}',
        '',
        'export function* generatorWithYield(): Generator<number> {',
        '  let i = 0;',
        '  while (true) {',
        '    yield i++;',
        '  }',
        '}',
        '',
        'export function* generatorForWithYield(): Generator<number> {',
        '  for (;;) {',
        '    yield 1;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(facts.map((fact) => fact.kind)).toEqual([]);
  });
});
