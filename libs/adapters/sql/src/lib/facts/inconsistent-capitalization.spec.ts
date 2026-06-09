import { collectInconsistentCapitalizationFacts } from './inconsistent-capitalization';

describe('inconsistent-capitalization', () => {
  it('detects inconsistent capitalization of identifiers', () => {
    const sql = 'SELECT * FROM Users WHERE users.id IN (SELECT id FROM users)';
    const facts = collectInconsistentCapitalizationFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.inconsistent-capitalization');
  });

  it('passes consistent capitalization', () => {
    const sql = 'SELECT * FROM users WHERE users.id IN (SELECT id FROM users)';
    const facts = collectInconsistentCapitalizationFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes consistent PascalCase identifiers', () => {
    const sql = 'SELECT * FROM Users WHERE Users.id IN (SELECT id FROM Users)';
    const facts = collectInconsistentCapitalizationFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('returns empty for empty input', () => {
    const facts = collectInconsistentCapitalizationFacts([], '');
    expect(facts).toHaveLength(0);
  });
});
