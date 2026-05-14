import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptCoreLanguageCorrectnessFacts } from './typescript-core-language-correctness';

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

  return collectTypescriptCoreLanguageCorrectnessFacts({
    nodeIds: new WeakMap(),
    path: 'src/core-language-sample.ts',
    program,
    sourceText: text,
  });
}

describe('collectTypescriptCoreLanguageCorrectnessFacts', () => {
  it('emits public-directory-aligned core language hygiene facts', () => {
    const facts = analyze(
      [
        "import { foo } from './dep';",
        "import { bar } from './dep';",
        '',
        'function dupParams(p: any, p: any) {',
        '  return p;',
        '}',
        '',
        'const obj = { k: 1, k: 2 };',
        '',
        'const discriminant = 1;',
        'switch (discriminant) {',
        '  case 1:',
        '    break;',
        '  case 1:',
        '    break;',
        '}',
        '',
        'export function assignInCond(flag: boolean) {',
        '  if (flag = true) {',
        '    return flag;',
        '  }',
        '  return false;',
        '}',
        '',
        'export function directAssignInIf() {',
        '  let x = 0;',
        '  if (x = 1) {',
        '    return x;',
        '  }',
        '  return 0;',
        '}',
        '',
        'export async function asyncExecutor() {',
        '  await new Promise(async (resolve) => {',
        '    resolve(undefined);',
        '  });',
        '}',
        '',
        'foo = 1;',
        '',
        'let self = 1;',
        'self = self;',
        '',
        'const same = 3;',
        'if (same === same) {',
        '  return;',
        '}',
      ].join('\n'),
    );

    const kinds = facts.map((f) => f.kind).sort();

    expect(kinds).toEqual(
      [
        'language.assignment-in-condition',
        'language.assignment-in-condition',
        'language.assignment-to-import-binding',
        'language.async-promise-executor',
        'language.duplicate-function-parameter',
        'language.duplicate-import-source',
        'language.duplicate-object-key',
        'language.duplicate-switch-case',
        'language.identical-comparison-operands',
        'language.self-assignment',
      ].sort(),
    );
  });

  it('still surfaces assignment conditions when grouping parentheses are elided by the parser', () => {
    const facts = analyze(
      [
        'export function groupedAssign(flag: boolean) {',
        '  if ((flag = true)) {',
        '    return flag;',
        '  }',
        '  return false;',
        '}',
      ].join('\n'),
    );

    expect(facts.filter((f) => f.kind === 'language.assignment-in-condition')).toHaveLength(1);
  });

  it('does not flag assignment wrapped in a comparison in the condition test', () => {
    const facts = analyze(
      [
        'export function readLoop() {',
        '  let line: string | null;',
        '  while ((line = next()) != null) {',
        '    void line;',
        '  }',
        '}',
        '',
        'function next(): string | null {',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(facts.filter((f) => f.kind === 'language.assignment-in-condition')).toHaveLength(0);
  });

  it('flags empty blocks outside function bodies but allows empty arrow bodies', () => {
    const facts = analyze(
      [
        'export function emptyIf(x: boolean) {',
        '  if (x) {}',
        '}',
        '',
        'export const noop = () => {};',
        '',
        'export function emptyTry() {',
        '  try {',
        '  } catch {',
        '  }',
        '}',
      ].join('\n'),
    );

    const emptyBlocks = facts.filter((f) => f.kind === 'language.empty-block-statement');
    expect(emptyBlocks).toHaveLength(3);
  });

  it('flags catch binding reassignment for outer and inner catch clauses separately', () => {
    const facts = analyze(
      [
        'export function outerCatch() {',
        '  try {',
        '    void 0;',
        '  } catch (e) {',
        '    e = new Error("mutate");',
        '    try {',
        '      void 0;',
        '    } catch (e) {',
        '      e = new Error("inner");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    );

    const reassign = facts.filter((f) => f.kind === 'language.reassign-catch-binding');
    expect(reassign).toHaveLength(2);
    expect(reassign.every((f) => f.props['binding'] === 'e')).toBe(true);
  });

  it('flags regexp patterns with unusual ASCII control characters', () => {
    const raw = analyze(`export const r = /${String.fromCharCode(1)}/;\n`);

    expect(
      raw.filter((f) => f.kind === 'language.regexp-pattern-unusual-control-character'),
    ).toHaveLength(1);

    const fromHexEscape = analyze('export const r = /\\x02/;\n');

    expect(
      fromHexEscape.filter((f) => f.kind === 'language.regexp-pattern-unusual-control-character'),
    ).toHaveLength(1);

    const fromUnicodeEscape = analyze('export const r = /\\u0002/;\n');

    expect(
      fromUnicodeEscape.filter((f) => f.kind === 'language.regexp-pattern-unusual-control-character'),
    ).toHaveLength(1);
  });

  it('does not flag common whitespace escapes or a literal backslash before x-like text', () => {
    const tab = analyze('export const r = /\\t/;\n');

    expect(
      tab.filter((f) => f.kind === 'language.regexp-pattern-unusual-control-character'),
    ).toHaveLength(0);

    const escapedBackslash = analyze('export const r = /\\\\x02/;\n');

    expect(
      escapedBackslash.filter((f) => f.kind === 'language.regexp-pattern-unusual-control-character'),
    ).toHaveLength(0);
  });
});
