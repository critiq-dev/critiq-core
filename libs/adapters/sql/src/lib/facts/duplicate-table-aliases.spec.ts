import { collectDuplicateTableAliasesFacts } from './duplicate-table-aliases';

describe('duplicate-table-aliases', () => {
  it('detects duplicate table alias', () => {
    const sql = 'SELECT * FROM users AS u JOIN orders AS u ON u.id = u.user_id';
    const facts = collectDuplicateTableAliasesFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.duplicate-table-aliases');
    expect(facts[0]?.props?.['alias']).toBe('u');
  });

  it('passes unique table aliases', () => {
    const sql = 'SELECT * FROM users AS u JOIN orders AS o ON u.id = o.user_id';
    const facts = collectDuplicateTableAliasesFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes no aliases', () => {
    const sql = 'SELECT * FROM users JOIN orders ON users.id = orders.user_id';
    const facts = collectDuplicateTableAliasesFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
