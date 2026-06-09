import { collectImplicitColumnAliasFacts } from './implicit-column-alias';

describe('implicit-column-alias', () => {
  it('detects implicit column alias', () => {
    const sql = 'SELECT name n, age a FROM users';
    const facts = collectImplicitColumnAliasFacts([], sql);
    expect(facts.length).toBeGreaterThanOrEqual(2);
    expect(facts[0]?.kind).toBe('sql.style.implicit-column-alias');
  });

  it('passes explicit column aliases with AS', () => {
    const sql = 'SELECT name AS n, age AS a FROM users';
    const facts = collectImplicitColumnAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes columns without aliases', () => {
    const sql = 'SELECT name, age FROM users';
    const facts = collectImplicitColumnAliasFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
