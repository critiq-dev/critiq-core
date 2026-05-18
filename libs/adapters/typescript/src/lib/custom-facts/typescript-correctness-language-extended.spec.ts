import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptCorrectnessLanguageExtendedFacts } from './typescript-correctness-language-extended';

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

  return collectTypescriptCorrectnessLanguageExtendedFacts({
    nodeIds: new WeakMap(),
    path: 'src/correctness-extended-sample.ts',
    program,
    sourceText: text,
  });
}

function kinds(text: string): string[] {
  return analyze(text)
    .map((fact) => fact.kind)
    .sort();
}

describe('collectTypescriptCorrectnessLanguageExtendedFacts', () => {
  it('flags control flow inside finally blocks', () => {
    const facts = analyze(
      [
        'export function riskyFinally() {',
        '  try {',
        '    return 1;',
        '  } finally {',
        '    return 2;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(
      facts.filter((fact) => fact.kind === 'language.control-flow-in-finally'),
    ).toHaveLength(1);
  });

  it('flags NaN identity comparisons and invalid typeof strings', () => {
    const facts = kinds(
      [
        'export function nanAndTypeof(value: unknown) {',
        '  if (value === NaN) {',
        '    return;',
        '  }',
        '  if (typeof value === "array") {',
        '    return;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(facts).toEqual(
      [
        'language.invalid-typeof-comparison',
        'language.use-number-is-nan',
      ].sort(),
    );
  });

  it('flags duplicate if-else-if conditions', () => {
    const facts = analyze(
      [
        'export function dupBranch(x: number) {',
        '  if (x === 1) {',
        '    return "one";',
        '  } else if (x === 1) {',
        '    return "also one";',
        '  }',
        '  return "other";',
        '}',
      ].join('\n'),
    );

    expect(
      facts.filter((fact) => fact.kind === 'language.duplicate-if-else-condition'),
    ).toHaveLength(1);
  });

  it('flags array callbacks without return and bare sort calls', () => {
    const facts = kinds(
      [
        'export function arrayHelpers(items: number[]) {',
        '  items.map((value) => {',
        '    console.log(value);',
        '  });',
        '  items.sort();',
        '}',
      ].join('\n'),
    );

    expect(facts).toEqual(
      [
        'language.array-callback-missing-return',
        'language.array-sort-without-compare',
      ].sort(),
    );
  });

  it('flags non-Error promise rejection and async throws', () => {
    const facts = kinds(
      [
        'export async function rejectPatterns() {',
        '  await Promise.reject("boom");',
        '  await new Promise((resolve, reject) => {',
        '    reject("inner");',
        '  });',
        '  throw "async";',
        '}',
      ].join('\n'),
    );

    expect(facts.filter((kind) => kind === 'language.promise-reject-non-error')).toHaveLength(3);
  });

  it('flags missing super and this before super in subclasses', () => {
    const missingSuper = analyze(
      [
        'class Base { value = 1; }',
        'class Child extends Base {',
        '  constructor() {',
        '    this.value = 2;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(
      missingSuper.filter((fact) => fact.kind === 'language.missing-super-call'),
    ).toHaveLength(1);

    const beforeSuper = analyze(
      [
        'class Base { value = 1; }',
        'class Child extends Base {',
        '  constructor() {',
        '    this.value = 2;',
        '    super();',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(
      beforeSuper.filter((fact) => fact.kind === 'language.this-before-super'),
    ).toHaveLength(1);
  });

  it('flags for-in loops over array-like values', () => {
    const facts = analyze(
      [
        'export function iterate(items: number[]) {',
        '  for (const key in items) {',
        '    console.log(key);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(facts.filter((fact) => fact.kind === 'language.for-in-on-array')).toHaveLength(1);
  });

  it('allows valid patterns', () => {
    const facts = kinds(
      [
        'export function valid(value: unknown) {',
        '  if (Number.isNaN(value)) {',
        '    return;',
        '  }',
        '  if (typeof value === "string") {',
        '    return;',
        '  }',
        '  const items = [1, 2];',
        '  items.map((entry) => entry + 1);',
        '  items.sort((left, right) => left - right);',
        '  for (const entry of items) {',
        '    void entry;',
        '  }',
        '  return Promise.reject(new Error("fail"));',
        '}',
      ].join('\n'),
    );

    expect(facts).toEqual([]);
  });
});
