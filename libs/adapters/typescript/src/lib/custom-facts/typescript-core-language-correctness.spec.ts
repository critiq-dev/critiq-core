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

  it('flags batch-01 core language hygiene facts', () => {
    const facts = analyze(
      [
        'export const emptyClass = /[]/;',
        'function declared() {}',
        'declared = function () {};',
        'if (true) {',
        '  function nested() {}',
        '  var nestedVar = 1;',
        '}',
        'export const invalidCtor = new RegExp("[");',
        'export const unsafeNegation = !key in object;',
        'export function callGlobal() {',
        '  return Math();',
        '}',
        'export function protoBuiltin(obj: object) {',
        '  return obj.hasOwnProperty("x");',
        '}',
        'export const sparse = [1, , 3];',
        'export const safeProto = Object.prototype.hasOwnProperty.call(obj, "x");',
        'export const dense = [1, 2, 3];',
        'export const validClass = /[a]/;',
      ].join('\n'),
    );

    expect(facts.filter((f) => f.kind === 'language.regexp-empty-character-class')).toHaveLength(1);
    expect(facts.filter((f) => f.kind === 'language.reassign-function-declaration')).toHaveLength(1);
    expect(facts.filter((f) => f.kind === 'language.declaration-in-nested-block')).toHaveLength(2);
    expect(facts.filter((f) => f.kind === 'language.regexp-constructor-invalid-pattern')).toHaveLength(
      1,
    );
    expect(facts.filter((f) => f.kind === 'language.unsafe-negation-in-relational')).toHaveLength(1);
    expect(facts.filter((f) => f.kind === 'language.global-object-called-as-function')).toHaveLength(
      1,
    );
    expect(facts.filter((f) => f.kind === 'language.prototype-builtin-called-directly')).toHaveLength(
      1,
    );
    expect(facts.filter((f) => f.kind === 'language.sparse-array-literal')).toHaveLength(1);
  });

  it('flags new Symbol() instantiation (JS-0233)', () => {
    const facts = analyze('const s = new Symbol("foo");\n');
    expect(facts.filter((f) => f.kind === 'language.new-symbol-instance')).toHaveLength(1);
  });

  it('does not flag Symbol() call as function', () => {
    const facts = analyze('const s = Symbol("foo");\n');
    expect(facts.filter((f) => f.kind === 'language.new-symbol-instance')).toHaveLength(0);
  });

  it('flags var declarations (JS-0239)', () => {
    const facts = analyze('var x = 1;\n');
    expect(facts.filter((f) => f.kind === 'language.var-declaration')).toHaveLength(1);
  });

  it('does not flag let/const declarations', () => {
    const facts = analyze('let x = 1;\nconst y = 2;\n');
    expect(facts.filter((f) => f.kind === 'language.var-declaration')).toHaveLength(0);
  });

  it('flags parseInt on number literal (JS-0253)', () => {
    const facts = analyze('parseInt(42, 10);\n');
    expect(facts.filter((f) => f.kind === 'language.parse-int-on-number-literal')).toHaveLength(1);
  });

  it('flags Number.parseInt on number literal', () => {
    const facts = analyze('Number.parseInt(42);\n');
    expect(facts.filter((f) => f.kind === 'language.parse-int-on-number-literal')).toHaveLength(1);
  });

  it('does not flag parseInt on string literal', () => {
    const facts = analyze('parseInt("42", 10);\n');
    expect(facts.filter((f) => f.kind === 'language.parse-int-on-number-literal')).toHaveLength(0);
  });

  it('flags assignment to exports in CJS context (JS-0256)', () => {
    const facts = analyze('exports = { foo: 1 };\n');
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(1);
  });

  it('does not flag exports.foo = bar', () => {
    const facts = analyze('exports.foo = 1;\n');
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(0);
  });

  it('does not flag assignment to exports in ESM context', () => {
    const facts = analyze("import { foo } from 'bar';\nexports = { foo };\n");
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(0);
  });

  it('does not flag exports = module.exports (re-syncing after mutation)', () => {
    const facts = analyze('exports = module.exports;\n');
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(0);
  });

  it('does not flag exports = module.exports = X (chained assignment)', () => {
    const facts = analyze('exports = module.exports = createApplication;\n');
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(0);
  });

  it('does not flag var app = exports = module.exports = {} (chained var decl)', () => {
    const facts = analyze('var app = exports = module.exports = {};\n');
    expect(facts.filter((f) => f.kind === 'language.assignment-to-exports')).toHaveLength(0);
  });

  it('flags callback missing error handling (JS-0254)', () => {
    const facts = analyze(
      [
        'import * as fs from "fs";',
        'fs.readFile("/path", (err, data) => {',
        '  console.log(data);',
        '});',
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.callback-missing-error-handling')).toHaveLength(1);
  });

  it('does not flag callback that uses error param', () => {
    const facts = analyze(
      [
        'import * as fs from "fs";',
        'fs.readFile("/path", (err, data) => {',
        '  if (err) throw err;',
        '  console.log(data);',
        '});',
      ].join('\n'),
    );
    expect(facts.filter((f) => f.kind === 'language.callback-missing-error-handling')).toHaveLength(0);
  });

  it('flags non-error-first callback (JS-0255) outside array methods', () => {
    const facts = analyze(
      [
        'import * as fs from "fs";',
        'fs.readFile("/path", (data, cb) => {',
        '  void cb;',
        '});',
      ].join('\n'),
    );

    expect(facts.filter((f) => f.kind === 'language.callback-not-error-first')).toHaveLength(1);
  });

  it('does not flag array method callbacks as non-error-first', () => {
    const facts = analyze(
      '[1, 2, 3].map((item) => item * 2);\n',
    );
    expect(facts.filter((f) => f.kind === 'language.callback-not-error-first')).toHaveLength(0);
  });

  it('does not flag .then callback as non-error-first', () => {
    const facts = analyze(
      'Promise.resolve(1).then((result) => result);\n',
    );
    expect(facts.filter((f) => f.kind === 'language.callback-not-error-first')).toHaveLength(0);
  });

  it('flags new require() expression (JS-0261)', () => {
    const facts = analyze(
      'const fs = new (require(\'fs\'))();\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(1);
  });

  it('flags bare new require() as direct constructor call', () => {
    const facts = analyze(
      'new require(\'fs\');\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(1);
  });

  it('does not flag new require().Member access (valid constructor)', () => {
    const facts = analyze(
      'const r = new (require(\'express\').Router)();\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(0);
  });

  it('does not flag bare require() call', () => {
    const facts = analyze(
      'const fs = require(\'fs\');\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(0);
  });

  it('does not flag normal new expression', () => {
    const facts = analyze(
      'const map = new Map();\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(0);
  });

  it('does not flag new require.resolve()', () => {
    const facts = analyze(
      'const resolved = new require.resolve(\'fs\');\n',
    );
    expect(facts.filter((f) => f.kind === 'language.new-expression-with-require')).toHaveLength(0);
  });

  describe('language.require-outside-import (JS-0359)', () => {
    it('flags require() call outside import', () => {
      const facts = analyze("const fs = require('fs');\n");
      expect(facts.filter((f) => f.kind === 'language.require-outside-import')).toHaveLength(1);
    });

    it('flags require.resolve() as require usage', () => {
      const facts = analyze(
        "const resolved = require.resolve('fs');\n",
      );
      expect(facts.filter((f) => f.kind === 'language.require-outside-import')).toHaveLength(1);
    });

    it('does not flag require() inside import x = require()', () => {
      const facts = analyze(
        "import fs = require('fs');\n",
      );
      expect(facts.filter((f) => f.kind === 'language.require-outside-import')).toHaveLength(0);
    });

    it('does not flag normal import', () => {
      const facts = analyze(
        "import * as fs from 'fs';\n",
      );
      expect(facts.filter((f) => f.kind === 'language.require-outside-import')).toHaveLength(0);
    });
  });

  describe('language.prefer-includes-over-indexof (JS-0363)', () => {
    it('flags arr.indexOf(x) !== -1', () => {
      const facts = analyze(
        'const found = arr.indexOf(x) !== -1;\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-includes-over-indexof')).toHaveLength(1);
    });

    it('flags arr.indexOf(x) >= 0', () => {
      const facts = analyze(
        'const found = arr.indexOf(x) >= 0;\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-includes-over-indexof')).toHaveLength(1);
    });

    it('flags !(arr.indexOf(x) === -1)', () => {
      const facts = analyze(
        'const found = !(arr.indexOf(x) === -1);\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-includes-over-indexof')).toHaveLength(
        1,
      );
    });

    it('does not flag legitimate indexOf usage', () => {
      const facts = analyze(
        'const idx = arr.indexOf(x);\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-includes-over-indexof')).toHaveLength(0);
    });
  });

  describe('language.unused-expression (JS-B003)', () => {
    it('flags pure logical expression as statement', () => {
      const facts = analyze(
        'export function test() { a && b; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(1);
    });

    it('flags literal as statement', () => {
      const facts = analyze(
        'export function test() { 42; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(1);
    });

    it('flags identifier reference as statement', () => {
      const facts = analyze(
        'export function test() { const x = 1; x; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(1);
    });

    it('does not flag function call expression', () => {
      const facts = analyze(
        'export function test() { foo(); }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(0);
    });

    it('does not flag assignment expression', () => {
      const facts = analyze(
        'export function test() { let x; x = 5; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(0);
    });

    it('does not flag directive prologue', () => {
      const facts = analyze(
        "'use strict';\nexport const x = 1;\n",
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(0);
    });

    it('does not flag logical expression with side-effectful right side', () => {
      const facts = analyze(
        'export function test() { a && b(); }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(0);
    });

    it('does not flag new expression', () => {
      const facts = analyze(
        'export function test() { new Foo(); }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.unused-expression')).toHaveLength(0);
    });
  });

  describe('language.prefer-nullish-coalescing (JS-0365)', () => {
    it('flags a || defaultValue pattern', () => {
      const facts = analyze(
        'export const result = value || defaultValue;\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-nullish-coalescing')).toHaveLength(1);
    });

    it('does not flag a || false where false is a valid value', () => {
      const facts = analyze(
        'export const result = flag || true;\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-nullish-coalescing')).toHaveLength(0);
    });

    it('flags a !== undefined ? a : b ternary', () => {
      const facts = analyze(
        'export const result = x !== undefined ? x : fallback;\n',
      );
      expect(facts.filter((f) => f.kind === 'language.prefer-nullish-coalescing')).toHaveLength(1);
    });
  });
});
