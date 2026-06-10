import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptClassAndSyntaxCorrectnessFacts } from './typescript-class-and-syntax-correctness';
import { collectTypescriptScopeCorrectnessFacts } from './typescript-scope-correctness';

function analyzeClass(text: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectTypescriptClassAndSyntaxCorrectnessFacts({
    nodeIds: new WeakMap(),
    path: 'src/class-syntax-sample.ts',
    program,
    sourceText: text,
  });
}

function analyzeScope(text: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectTypescriptScopeCorrectnessFacts({
    nodeIds: new WeakMap(),
    path: 'src/scope-sample.ts',
    program,
    sourceText: text,
  });
}

describe('collectTypescriptClassAndSyntaxCorrectnessFacts', () => {
  it('flags negative zero comparisons and template placeholders in strings', () => {
    const kinds = analyzeClass(
      [
        'export function compare(value: number) {',
        '  return value === -0;',
        '}',
        'export const message = "${name}";',
      ].join('\n'),
    )
      .map((fact) => fact.kind)
      .sort();

    expect(kinds).toEqual(
      [
        'language.negative-zero-comparison',
        'language.template-placeholder-in-string',
      ].sort(),
    );
  });

  it('flags class member issues and constructor return values', () => {
    const kinds = analyzeClass(
      [
        'class Example {',
        '  value = 1;',
        '  constructor() {',
        '    return { ok: true };',
        '  }',
        '  set value(next: number) {',
        '    return next;',
        '  }',
        '  value = 2;',
        '  run() {',
        '    this.value = 3;',
        '  }',
        '}',
      ].join('\n'),
    )
      .map((fact) => fact.kind)
      .sort();

    expect(kinds).toEqual(
      expect.arrayContaining([
        'language.constructor-return-value',
        'language.duplicate-class-member',
        'language.reassign-class-member',
        'language.setter-return-value',
      ]),
    );
    expect(kinds.filter((kind) => kind === 'language.duplicate-class-member').length).toBeGreaterThanOrEqual(1);
  });

  it('flags switch fallthrough, empty destructuring, delete on variables, and invalid this', () => {
    const kinds = analyzeClass(
      [
        'export function patterns(input: number) {',
        '  switch (input) {',
        '    case 1:',
        '      console.log("one");',
        '    case 2:',
        '      return input;',
        '  }',
        '  const {} = input;',
        '  delete localVar;',
        '  return input;',
        '  let localVar = 1;',
        '}',
        'const moduleThis = this;',
      ].join('\n'),
    )
      .map((fact) => fact.kind)
      .sort();

    expect(kinds).toEqual(
      [
        'language.delete-on-variable',
        'language.empty-destructuring-pattern',
        'language.invalid-variable-usage',
        'language.switch-case-fallthrough',
        'language.this-outside-class',
      ].sort(),
    );
  });
});

describe('collectTypescriptScopeCorrectnessFacts', () => {
  it('flags undeclared, unused, used-before-definition, restricted globals, and const reassignment', () => {
    const kinds = analyzeScope(
      [
        'export function scopeIssues() {',
        '  console.log(missingBinding);',
        '  let unused = 1;',
        '  console.log(later);',
        '  let later = 2;',
        '  const fixed = 1;',
        '  fixed = 2;',
        '  return event;',
        '}',
      ].join('\n'),
    )
      .map((fact) => fact.kind)
      .sort();

    expect(kinds).toEqual(
      [
        'language.reassign-const-binding',
        'language.restricted-global-variable',
        'language.undeclared-variable',
        'language.unused-variable',
        'language.used-before-definition',
      ].sort(),
    );
  });

  it('flags extraneous imports (JS-0257)', () => {
    const facts = analyzeScope(
      [
        "import { unused } from './dep';",
        "import { used } from './dep2';",
        '',
        'const x = used;',
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.extraneous-import')).toHaveLength(1);
  });

  it('does not flag used imports', () => {
    const facts = analyzeScope(
      [
        "import { used } from './dep';",
        '',
        'const x = used;',
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.extraneous-import')).toHaveLength(0);
  });

  it('does not flag side-effect imports', () => {
    const facts = analyzeScope(
      [
        "import './polyfill';",
        "import { used } from './dep';",
        '',
        'const x = used;',
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.extraneous-import')).toHaveLength(0);
  });

  it('does not flag type-only imports', () => {
    const facts = analyzeScope(
      [
        "import type { Foo } from './types';",
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.extraneous-import')).toHaveLength(0);
  });
});
