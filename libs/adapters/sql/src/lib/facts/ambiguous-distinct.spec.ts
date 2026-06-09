import { collectAmbiguousDistinctFacts } from './ambiguous-distinct';

describe('ambiguous-distinct', () => {
  it('detects ambiguous DISTINCT with computed columns', () => {
    const sql = 'SELECT DISTINCT dept, mgr, COUNT(*) FROM emp';
    const facts = collectAmbiguousDistinctFacts([], sql);
    expect(facts.length).toBeGreaterThanOrEqual(1);
    expect(facts[0]?.kind).toBe('sql.style.ambiguous-distinct');
  });

  it('passes DISTINCT with simple columns', () => {
    const sql = 'SELECT DISTINCT dept FROM emp';
    const facts = collectAmbiguousDistinctFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes DISTINCT with qualified columns', () => {
    const sql = 'SELECT DISTINCT emp.dept, emp.mgr FROM emp';
    const facts = collectAmbiguousDistinctFacts([], sql);
    expect(facts).toHaveLength(0);
  });

  it('passes non-DISTINCT queries', () => {
    const sql = 'SELECT dept, mgr, COUNT(*) FROM emp';
    const facts = collectAmbiguousDistinctFacts([], sql);
    expect(facts).toHaveLength(0);
  });
});
