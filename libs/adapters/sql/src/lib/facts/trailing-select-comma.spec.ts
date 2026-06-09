import { collectTrailingSelectCommaFacts } from './trailing-select-comma';

describe('trailing-select-comma', () => {
  it('detects trailing comma before FROM', () => {
    const sql = 'SELECT a, b, FROM foo';
    const facts = collectTrailingSelectCommaFacts([], sql);
    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('sql.style.trailing-select-comma');
  });

  it('passes no trailing comma', () => {
    const sql = 'SELECT a, b FROM foo';
    const facts = collectTrailingSelectCommaFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes comma mid-SELECT not before FROM', () => {
    const sql = 'SELECT a, b, c FROM foo';
    const facts = collectTrailingSelectCommaFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('ignores trailing comma inside comments', () => {
    const sql = '-- SELECT a, b, FROM foo\nSELECT a, b FROM foo';
    const facts = collectTrailingSelectCommaFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('detects trailing comma with newline before FROM', () => {
    const sql = 'SELECT a, b,\nFROM foo';
    const facts = collectTrailingSelectCommaFacts([], sql);
    expect(facts).toHaveLength(1);
  });
});
