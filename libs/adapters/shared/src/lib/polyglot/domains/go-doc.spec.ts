import {
  collectGoDocFacts,
  GO_DOC_FACT_KINDS,
} from './go-doc';

describe('go-doc collectors', () => {
  describe('malformed deprecated comment', () => {
    it('flags lowercase "d" in deprecated comment', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '// deprecated, use Foo instead',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_DOC_FACT_KINDS.malformedDeprecatedComment,
      );
      expect(facts[0].text).toBe('// deprecated');
    });

    it('flags capital D without colon', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '// Deprecated, use Foo instead',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_DOC_FACT_KINDS.malformedDeprecatedComment,
      );
    });

    it('flags leading whitespace before deprecated', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '//  deprecated use Foo',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_DOC_FACT_KINDS.malformedDeprecatedComment,
      );
    });

    it('does not flag valid Deprecated: with colon', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '// Deprecated: use Foo instead',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag minimal valid Deprecated:', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '// Deprecated:',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag string literal containing deprecated', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'var s = "// deprecated, this is a string"',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag backtick literal containing deprecated', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'var s = `// deprecated`',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag function name containing Deprecated', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func DeprecatedFoo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag block comment with deprecated', () => {
      const facts = collectGoDocFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          '/* deprecated */',
          'func Foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_DOC_FACT_KINDS.malformedDeprecatedComment,
        ),
      ).toHaveLength(0);
    });
  });
});
