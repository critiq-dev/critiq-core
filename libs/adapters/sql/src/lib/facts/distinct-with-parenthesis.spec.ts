import { collectDistinctWithParenthesisFacts } from './distinct-with-parenthesis';

describe('distinct-with-parenthesis', () => {
  it('detects DISTINCT with parenthesis', () => {
    const sql = 'SELECT DISTINCT(name) FROM users';
    const facts = collectDistinctWithParenthesisFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.distinct-with-parenthesis');
  });

  it('passes DISTINCT without parenthesis', () => {
    const sql = 'SELECT DISTINCT name FROM users';
    const facts = collectDistinctWithParenthesisFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes no DISTINCT at all', () => {
    const sql = 'SELECT name FROM users';
    const facts = collectDistinctWithParenthesisFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
