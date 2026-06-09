import { collectInconsistentKeywordCaseFacts } from './inconsistent-keyword-case';

describe('inconsistent-keyword-case', () => {
  it('detects mixed keyword casing (SELECT + and)', () => {
    const sql = "SELECT * FROM users WHERE name = 'x' and age > 1";
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.inconsistent-keyword-case');
  });

  it('passes consistent keyword casing', () => {
    const sql = "SELECT * FROM users WHERE name = 'x' AND age > 1";
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes all lowercase keywords', () => {
    const sql = "select * from users where name = 'x' and age > 1";
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects mixed casing with multiple keywords', () => {
    const sql = 'SELECT * FROM users LEFT join orders ON u.id = o.user_id';
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.inconsistent-keyword-case');
  });

  it('returns empty for empty input', () => {
    const facts = collectInconsistentKeywordCaseFacts([], '');
    expect(facts).toHaveLength(0);
  });

  it('ignores keywords inside comments', () => {
    const sql = "-- comment with select and table\nSELECT * FROM users WHERE id = 1";
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('still detects mixed casing with real SQL keywords', () => {
    const sql = "-- harmless comment\nSELECT * FROM users WHERE name = 'x' and age > 1";
    const facts = collectInconsistentKeywordCaseFacts([], sql);
    expect(facts).toHaveLength(1);
  });
});
