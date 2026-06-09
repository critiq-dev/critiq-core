import { collectUndefinedReferenceFacts } from './undefined-reference';

describe('undefined-reference', () => {
  it('detects undefined table reference', () => {
    const sql = 'SELECT vee.a FROM foo';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.correctness.undefined-reference');
    expect(facts[0]?.props?.['qualifier']).toBe('vee');
  });

  it('passes valid reference', () => {
    const sql = 'SELECT foo.a FROM foo';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes when no references exist', () => {
    const sql = 'SELECT a FROM foo';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes schema-qualified table names', () => {
    const sql = 'SELECT a FROM schema.foo';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes alias-qualified references', () => {
    const sql = 'SELECT f.a FROM foo AS f';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes table-qualified references', () => {
    const sql = 'SELECT foo.a, bar.b FROM foo JOIN bar ON foo.id = bar.id';
    const facts = collectUndefinedReferenceFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
