import { collectImplicitTableAliasFacts } from './implicit-table-alias';

describe('implicit-table-alias', () => {
  it('detects implicit table alias', () => {
    const sql = 'SELECT * FROM users u JOIN orders o ON u.id = o.user_id';
    const facts = collectImplicitTableAliasFacts([], sql);
    expect(facts.length).toBeGreaterThanOrEqual(2);
    expect(facts[0]?.kind).toBe('sql.style.implicit-table-alias');
  });

  it('passes explicit table aliases with AS', () => {
    const sql = 'SELECT * FROM users AS u JOIN orders AS o ON u.id = o.user_id';
    const facts = collectImplicitTableAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes tables without aliases', () => {
    const sql = 'SELECT * FROM users JOIN orders ON users.id = orders.user_id';
    const facts = collectImplicitTableAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects implicit alias in simple FROM', () => {
    const sql = 'SELECT * FROM users u';
    const facts = collectImplicitTableAliasFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.props?.['alias']).toBe('u');
    expect(facts[0]?.props?.['table']).toBe('users');
  });
});
