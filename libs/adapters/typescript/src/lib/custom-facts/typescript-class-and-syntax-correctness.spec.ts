import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptClassAndSyntaxCorrectnessFacts } from './typescript-class-and-syntax-correctness';

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

  return collectTypescriptClassAndSyntaxCorrectnessFacts({
    nodeIds: new WeakMap(),
    path: 'src/class-syntax-sample.ts',
    program,
    sourceText: text,
  });
}

function kinds(text: string): string[] {
  return analyze(text)
    .map((fact) => fact.kind)
    .sort();
}

describe('collectTypescriptClassAndSyntaxCorrectnessFacts', () => {
  describe('language.this-outside-class (JS-B002)', () => {
    it('flags this at module level', () => {
      const facts = analyze('const x = this;\nexport {};\n');
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(1);
    });

    it('flags this inside standalone function', () => {
      const facts = analyze(
        'export function foo() { return this; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(1);
    });

    it('flags this inside arrow function at module level', () => {
      const facts = analyze(
        'export const fn = () => { this.x = 1; };\n',
      );
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(1);
    });

    it('does not flag this inside class method', () => {
      const facts = analyze(
        'export class Foo { bar() { return this; } }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(0);
    });

    it('does not flag this inside class field initializer', () => {
      const facts = analyze(
        'export class Foo { bar = this; }\n',
      );
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(0);
    });

    it('does not flag this inside object literal method', () => {
      const facts = analyze(
        'export const obj = { foo() { return this; } };\n',
      );
      expect(facts.filter((f) => f.kind === 'language.this-outside-class')).toHaveLength(0);
    });
  });

  describe('typescript.private-member-should-be-readonly (JS-0368)', () => {
    it('flags private member that is never mutated', () => {
      const facts = analyze(
        [
          'class Example {',
          '  private name: string;',
          '  constructor(n: string) {',
          '    this.name = n;',
          '  }',
          '  getName() {',
          '    return this.name;',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.private-member-should-be-readonly'),
      ).toHaveLength(1);
    });

    it('does not flag private member mutated in non-constructor method', () => {
      const facts = analyze(
        [
          'class Example {',
          '  private counter = 0;',
          '  increment() {',
          '    this.counter += 1;',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.private-member-should-be-readonly'),
      ).toHaveLength(0);
    });

    it('does not flag public member', () => {
      const facts = analyze(
        [
          'class Example {',
          '  name: string;',
          '  constructor(n: string) {',
          '    this.name = n;',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.private-member-should-be-readonly'),
      ).toHaveLength(0);
    });

    it('does not flag already readonly private member', () => {
      const facts = analyze(
        [
          'class Example {',
          '  private readonly name: string;',
          '  constructor(n: string) {',
          '    this.name = n;',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        facts.filter((f) => f.kind === 'typescript.private-member-should-be-readonly'),
      ).toHaveLength(0);
    });
  });
});
