import { analyzeSqlFile } from './sql';

describe('sql adapter', () => {
  describe('analyzeSqlFile', () => {
    it('returns success for valid SQL', () => {
      const result = analyzeSqlFile('test.sql', 'SELECT * FROM users');
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.language).toBe('sql');
        expect(result.data.path).toBe('test.sql');
        expect(result.data.text).toBe('SELECT * FROM users');
      }
    });

    it('returns success with facts for unparseable SQL', () => {
      const result = analyzeSqlFile('test.sql', 'SELECT a, b, FROM foo');
      expect(result.success).toBe(true);
      if (result.success) {
        const facts = result.data.semantics?.controlFlow?.facts ?? [];
        const trailingCommaFacts = facts.filter((f) => f.kind === 'sql.style.trailing-select-comma');
        expect(trailingCommaFacts.length).toBeGreaterThanOrEqual(1);
      }
    });

    it('includes facts in success result', () => {
      const result = analyzeSqlFile('test.sql', 'SELECT * FROM users');
      expect(result.success).toBe(true);
      if (result.success) {
        const facts = result.data.semantics?.controlFlow?.facts ?? [];
        expect(Array.isArray(facts)).toBe(true);
      }
    });

    it('does not return facts from comment content', () => {
      const result = analyzeSqlFile('test.sql', '-- SELECT COUNT(*) without alias\nSELECT * FROM users');
      expect(result.success).toBe(true);
      if (result.success) {
        const facts = result.data.semantics?.controlFlow?.facts ?? [];
        const expressionFacts = facts.filter((f) => f.kind === 'sql.style.column-expression-without-alias');
        const keywordFacts = facts.filter((f) => f.kind === 'sql.style.inconsistent-keyword-case');
        expect(expressionFacts).toHaveLength(0);
        expect(keywordFacts).toHaveLength(0);
      }
    });

    it('produces keyword-as-identifier fact for keyword alias', () => {
      const result = analyzeSqlFile('test.sql', 'SELECT sum.a FROM foo AS sum');
      expect(result.success).toBe(true);
      if (result.success) {
        const facts = result.data.semantics?.controlFlow?.facts ?? [];
        const kwFacts = facts.filter((f) => f.kind === 'sql.style.keyword-as-identifier');
        expect(kwFacts.length).toBeGreaterThanOrEqual(1);
      }
    });
  });
});
