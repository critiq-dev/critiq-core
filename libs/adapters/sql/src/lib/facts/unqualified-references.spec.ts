import { collectUnqualifiedReferencesFacts } from './unqualified-references';

describe('unqualified-references', () => {
  it('detects unqualified column references with 2 tables', () => {
    const sql = 'SELECT a, b FROM foo LEFT JOIN bar ON foo.id = bar.id';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.unqualified-references');
    expect(facts[0]?.props?.['unqualifiedColumns']).toContain('a');
    expect(facts[0]?.props?.['unqualifiedColumns']).toContain('b');
  });

  it('passes qualified references', () => {
    const sql = 'SELECT foo.a, bar.b FROM foo LEFT JOIN bar ON foo.id = bar.id';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes single table queries', () => {
    const sql = 'SELECT a FROM foo';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('flags unqualified in USING join (a not in USING columns)', () => {
    const sql = 'SELECT a FROM foo JOIN bar USING (id)';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.props?.['unqualifiedColumns']).toContain('a');
  });

  it('passes qualified references in USING join', () => {
    const sql = 'SELECT foo.a FROM foo JOIN bar USING (id)';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes when SELECT uses qualified refs with 2 tables', () => {
    const sql = 'SELECT foo.id, bar.name FROM foo JOIN bar ON foo.id = bar.id';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects unqualified with function in columns', () => {
    const sql = 'SELECT COUNT(*), a FROM foo JOIN bar ON foo.id = bar.id';
    const facts = collectUnqualifiedReferencesFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.props?.['unqualifiedColumns']).toContain('a');
  });
});
