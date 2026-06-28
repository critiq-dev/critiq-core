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

  it('emits misused-promises when async callback is NOT wrapped by Promise.all', () => {
    const facts = analyze(
      [
        'export function misused(): void {',
        '  [1, 2].map(async (value) => value + 1);',
        '}',
        '',
        'export function alsoMisused(items: string[]): void {',
        '  items.filter(async (item) => {',
        '    await loadSomething(item);',
        '    return true;',
        '  });',
        '}',
        '',
        'async function loadSomething(x: string): Promise<void> {}',
      ].join('\n'),
    );

    const kinds = facts.map((f) => f.kind);
    expect(kinds.filter((k) => k === 'async.misused-promises')).toHaveLength(2);
    expect(kinds).not.toContain('async.floating-promise-in-function');
  });

  it('ignores async map/filter when wrapped by Promise.all or Promise.allSettled', () => {
    const facts = analyze(
      [
        'async function fetchUser(id: number): Promise<{ id: number; name: string }> {',
        '  return { id, name: "user" + id };',
        '}',
        '',
        'export async function validParallelPattern(): Promise<{ id: number; name: string }[]> {',
        '  return await Promise.all([1, 2, 3].map(async (id) => fetchUser(id)));',
        '}',
        '',
        'export async function validAllSettled(): Promise<void> {',
        '  await Promise.allSettled([1, 2].map(async (n) => n * 2));',
        '}',
        '',
        'export async function validFilterWithPromiseAll(): Promise<number[]> {',
        '  const results = await Promise.all(',
        '    [1, 2, 3, 4].filter(async (n) => {',
        '      await fetchUser(n);',
        '      return n % 2 === 0;',
        '    }),',
        '  );',
        '  return results;',
        '}',
        '',
        'export async function validForEachWrapped(): Promise<void> {',
        '  const items = [1, 2, 3];',
        '  await Promise.all(items.map(async (n) => n * 2));',
        '}',
      ].join('\n'),
    );

    const kinds = facts.map((f) => f.kind);
    expect(kinds.filter((k) => k === 'async.misused-promises')).toHaveLength(0);
  });
});
