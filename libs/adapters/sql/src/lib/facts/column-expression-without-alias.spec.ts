import { collectColumnExpressionWithoutAliasFacts } from './column-expression-without-alias';

describe('column-expression-without-alias', () => {
  it('detects column expression without alias', () => {
    const sql = 'SELECT COUNT(*) FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts.length).toBeGreaterThanOrEqual(1);
    expect(facts[0]?.kind).toBe('sql.style.column-expression-without-alias');
  });

  it('passes column expression with alias', () => {
    const sql = 'SELECT COUNT(*) AS user_count FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes simple column refs without aliases', () => {
    const sql = 'SELECT name, age FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes star select', () => {
    const sql = 'SELECT * FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects function call without alias', () => {
    const sql = 'SELECT COUNT(*) FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts.length).toBeGreaterThanOrEqual(1);
  });

  it('passes DISTINCT with single column', () => {
    const sql = 'SELECT DISTINCT name FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes DISTINCT with column expression that has alias', () => {
    const sql = 'SELECT DISTINCT dept, COUNT(*) AS cnt FROM emp';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('ignores comments when detecting', () => {
    const sql = '-- SELECT COUNT(*) without alias\nSELECT * FROM users';
    const facts = collectColumnExpressionWithoutAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
