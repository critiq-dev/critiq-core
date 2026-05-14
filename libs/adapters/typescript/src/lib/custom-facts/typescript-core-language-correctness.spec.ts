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
});
