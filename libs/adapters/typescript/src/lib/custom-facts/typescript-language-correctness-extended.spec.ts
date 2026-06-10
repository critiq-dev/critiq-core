import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptLanguageCorrectnessExtendedFacts } from './typescript-language-correctness-extended';

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

  return collectTypescriptLanguageCorrectnessExtendedFacts({
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

describe('collectTypescriptLanguageCorrectnessExtendedFacts', () => {
  describe('language.invalid-shebang', () => {
    it('does not flag file with valid shebang at line 1 col 0', () => {
      const facts = analyze(
        '#!/usr/bin/env node\nconst x = 1;\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'language.invalid-shebang'),
      ).toHaveLength(0);
    });

    it('does not flag file without shebang', () => {
      const facts = analyze('const x = 1;\nexport {}');

      expect(
        facts.filter((f) => f.kind === 'language.invalid-shebang'),
      ).toHaveLength(0);
    });
  });

  describe('language.deprecated-api', () => {
    it('flags new Buffer() usage', () => {
      const facts = kinds('const buf = new Buffer(10);\nexport {}');

      expect(facts).toContain('language.deprecated-api');
    });

    it('flags url.parse() usage', () => {
      const facts = kinds(
        'import url from "url";\nurl.parse("http://example.com");\nexport {}',
      );

      expect(facts).toContain('language.deprecated-api');
    });

    it('flags domain.create() usage', () => {
      const facts = kinds('import domain from "domain";\ndomain.create();\nexport {}');

      expect(facts).toContain('language.deprecated-api');
    });

    it('flags deprecated React lifecycle methods', () => {
      const facts = kinds(
        'export const C = { componentWillMount() {} };\nexport {}',
      );

      expect(facts).toContain('language.deprecated-api');
    });

    it('allows modern Buffer.from()', () => {
      const facts = kinds('const buf = Buffer.from("hello");\nexport {}');

      expect(facts).not.toContain('language.deprecated-api');
    });

    it('allows new URL()', () => {
      const facts = kinds(
        'const u = new URL("http://example.com");\nexport {}',
      );

      expect(facts).not.toContain('language.deprecated-api');
    });
  });

  describe('language.invalid-async-await', () => {
    it('flags await outside async function', () => {
      const facts = kinds(
        'function sync() {\n  await Promise.resolve(1);\n}\nexport {}',
      );

      expect(facts).toContain('language.invalid-async-await');
    });

    it('flags for-await-of outside async function', () => {
      const facts = kinds(
        'function sync() {\n  for await (const x of []) {}\n}\nexport {}',
      );

      expect(facts).toContain('language.invalid-async-await');
    });

    it('allows await inside async function', () => {
      const facts = kinds(
        'async function asyncFn() {\n  await Promise.resolve(1);\n}\nexport {}',
      );

      expect(facts).not.toContain('language.invalid-async-await');
    });

    it('allows await in nested async arrow', () => {
      const facts = kinds(
        'async function outer() {\n  const fn = async () => await Promise.resolve(1);\n}\nexport {}',
      );

      expect(facts).not.toContain('language.invalid-async-await');
    });
  });

  describe('language.ts-suppress-directive', () => {
    it('flags @ts-ignore directive', () => {
      const facts = kinds(
        '// @ts-ignore\nconst x: any = 1;\nexport {}',
      );

      expect(facts).toContain('language.ts-suppress-directive');
    });

    it('flags @ts-nocheck directive', () => {
      const facts = kinds(
        '// @ts-nocheck\nexport {}',
      );

      expect(facts).toContain('language.ts-suppress-directive');
    });

    it('flags @ts-expect-error directive', () => {
      const facts = kinds(
        '// @ts-expect-error\nconst x: number = "string";\nexport {}',
      );

      expect(facts).toContain('language.ts-suppress-directive');
    });

    it('does not flag file without ts directives', () => {
      const facts = kinds(
        'const x: number = 1;\nexport {}',
      );

      expect(facts).not.toContain('language.ts-suppress-directive');
    });
  });

  describe('typescript.prefer-as-const-over-literal-type (JS-0360)', () => {
    it('flags variable with literal string type annotation', () => {
      const facts = analyze(
        'const x: "hello" = "hello";\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.prefer-as-const-over-literal-type'),
      ).toHaveLength(1);
    });

    it('does not flag variable with as const assertion', () => {
      const facts = analyze(
        'const x = "hello" as const;\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.prefer-as-const-over-literal-type'),
      ).toHaveLength(0);
    });

    it('does not flag variable without type annotation', () => {
      const facts = analyze(
        'const x = "hello";\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.prefer-as-const-over-literal-type'),
      ).toHaveLength(0);
    });
  });

  describe('typescript.missing-type-annotation (JS-0386)', () => {
    it('flags function parameter without type annotation', () => {
      const facts = analyze(
        'function greet(name) { return name; }\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.missing-type-annotation'),
      ).toHaveLength(1);
    });

    it('does not flag function parameter with type annotation', () => {
      const facts = analyze(
        'function greet(name: string) { return name; }\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.missing-type-annotation'),
      ).toHaveLength(0);
    });

    it('flags variable initialized to null without type annotation', () => {
      const facts = analyze(
        'const x = null;\nexport {}',
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.missing-type-annotation'),
      ).toHaveLength(1);
    });
  });
});
