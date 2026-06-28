import {
  collectJavaDocFacts,
  JAVA_DOC_FACT_KINDS,
} from './java-doc';

describe('java-doc collectors', () => {
  describe('unmatched @param tag (D1004)', () => {
    it('flags @param y when method has parameter x', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param y the value',
          '   */',
          '  void foo(int x) {}',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.unmatchedParameterTag,
      );
    });

    it('does not flag @param x when method has parameter x', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param x the value',
          '   */',
          '  void foo(int x) {}',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.unmatchedParameterTag,
        ),
      ).toHaveLength(0);
    });

    it('flags @param on method with no parameters', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param x does nothing',
          '   */',
          '  void foo() {}',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.unmatchedParameterTag,
      );
    });

    it('handles multiple params correctly', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param a first',
          '   * @param b second',
          '   * @param c third (unmatched)',
          '   */',
          '  void foo(int a, String b) {}',
          '}',
        ].join('\n'),
      });

      const unmatched = facts.filter(
        (f) => f.kind === JAVA_DOC_FACT_KINDS.unmatchedParameterTag,
      );

      expect(unmatched).toHaveLength(1);
      expect(unmatched[0].text).toContain('c');
    });
  });

  describe('@param tag with no description (D1005)', () => {
    it('flags @param name with trailing whitespace and no description', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param x',
          '   */',
          '  void foo(int x) {}',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.parameterTagNoDescription,
      );
    });

    it('does not flag @param name with description', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          'class Main {',
          '  /**',
          '   * @param x the value',
          '   */',
          '  void foo(int x) {}',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.parameterTagNoDescription,
        ),
      ).toHaveLength(0);
    });
  });

  describe('empty Javadoc tag (D1006)', () => {
    it('flags bare @param with nothing after', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @param',
          ' */',
          'void foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.emptyJavadocTag,
      );
    });

    it('flags bare @return with nothing after', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @return',
          ' */',
          'int foo() { return 1; }',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.emptyJavadocTag,
      );
    });

    it('does not flag @param with a name', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @param x description',
          ' */',
          'void foo(int x) {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.emptyJavadocTag,
        ),
      ).toHaveLength(0);
    });

    it('flags bare @throws with nothing after', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @throws',
          ' */',
          'void foo() throws Exception {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.emptyJavadocTag,
      );
    });

    it('flags bare @see with nothing after', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @see',
          ' */',
          'void foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.emptyJavadocTag,
      );
    });

    it('flags bare @since with nothing after', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @since',
          ' */',
          'void foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.emptyJavadocTag,
      );
    });

    it('does not flag @return with content', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @return the result',
          ' */',
          'int foo() { return 1; }',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.emptyJavadocTag,
        ),
      ).toHaveLength(0);
    });

    it('does not flag @param in a regular block comment (not Javadoc)', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/* just a regular comment with @param',
          ' */',
          'void foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.emptyJavadocTag,
        ),
      ).toHaveLength(0);
    });

    it('does not flag @return in a line comment (not Javadoc)', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '// @return',
          'void foo() { return; }',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.emptyJavadocTag,
        ),
      ).toHaveLength(0);
    });

    it('does not flag @deprecated outside Javadoc', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '// @deprecated since v2',
          '@Deprecated',
          'void foo() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.emptyJavadocTag,
        ),
      ).toHaveLength(0);
    });
  });

  describe('malformed Javadoc comment (D1007)', () => {
    it('flags @@param', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @@param x',
          ' */',
          'void foo() {}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        JAVA_DOC_FACT_KINDS.malformedJavadocComment,
      );
    });

    it('does not flag normal @param', () => {
      const facts = collectJavaDocFacts({
        detector: 'java-detector',
        text: [
          '/**',
          ' * @param x description',
          ' */',
          'void foo(int x) {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === JAVA_DOC_FACT_KINDS.malformedJavadocComment,
        ),
      ).toHaveLength(0);
    });
  });

  it('returns zero facts for source with no Javadoc comments', () => {
    const facts = collectJavaDocFacts({
      detector: 'java-detector',
      text: [
        'class Main {',
        '  void foo() {}',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
