import { collectUnusedTableAliasFacts } from './unused-table-alias';

describe('unused-table-alias', () => {
  it('detects unused table alias', () => {
    const sql = 'SELECT a FROM foo AS zoo';
    const facts = collectUnusedTableAliasFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.unused-table-alias');
    expect(facts[0]?.props?.['alias']).toBe('zoo');
  });

  it('passes used table alias', () => {
    const sql = 'SELECT zoo.a FROM foo AS zoo';
    const facts = collectUnusedTableAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes no aliases', () => {
    const sql = 'SELECT * FROM foo';
    const facts = collectUnusedTableAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes alias used in ON clause', () => {
    const sql = 'SELECT * FROM foo AS f JOIN bar AS b ON f.id = b.id';
    const facts = collectUnusedTableAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects unused implicit alias', () => {
    const sql = 'SELECT a FROM foo zoo';
    const facts = collectUnusedTableAliasFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.props?.['alias']).toBe('zoo');
  });
});
