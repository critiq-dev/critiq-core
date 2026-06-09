import { collectKeywordAsIdentifierFacts } from './keyword-as-identifier';

describe('keyword-as-identifier', () => {
  it('detects keyword used as alias (sum)', () => {
    const sql = 'SELECT sum.a FROM foo AS sum';
    const facts = collectKeywordAsIdentifierFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.keyword-as-identifier');
    expect(facts[0]?.props?.['alias']).toBe('sum');
    expect(facts[0]?.props?.['keyword']).toBe('SUM');
  });

  it('passes non-keyword alias (vee)', () => {
    const sql = 'SELECT vee.a FROM foo AS vee';
    const facts = collectKeywordAsIdentifierFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes no aliases', () => {
    const sql = 'SELECT a FROM foo';
    const facts = collectKeywordAsIdentifierFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('ignores aliases inside comments', () => {
    const sql = '-- SELECT sum.a FROM foo AS sum\nSELECT a FROM foo';
    const facts = collectKeywordAsIdentifierFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects implicit keyword alias without AS', () => {
    const sql = 'SELECT * FROM foo sum';
    const facts = collectKeywordAsIdentifierFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.props?.['alias']).toBe('sum');
  });
});
