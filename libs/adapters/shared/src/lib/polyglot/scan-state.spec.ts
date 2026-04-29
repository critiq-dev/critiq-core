import { collectTrackedIdentifiers } from './scan-state';

describe('collectTrackedIdentifiers', () => {
  it('propagates tainted and sql-interpolated identifiers through assignments', () => {
    const state = collectTrackedIdentifiers({
      text: [
        'payload = request.body',
        'query = `SELECT * FROM users WHERE id = ${payload}`',
        'safe = "value" # ignored comment',
        'nextPayload = payload',
        'nextQuery = query',
      ].join('\n'),
      assignmentPattern: /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/u,
      stripLineComment: (line) => line.replace(/#.*$/u, ''),
      seedTaintedIdentifiers: ['request'],
      isTaintedExpression: (expression, identifiers) =>
        expression.includes('request.body') ||
        [...identifiers].some((identifier) => expression.includes(identifier)),
      isSqlInterpolatedExpression: (expression, identifiers) =>
        expression.includes('SELECT') ||
        [...identifiers].some((identifier) => expression.includes(identifier)),
    });

    expect([...state.taintedIdentifiers]).toEqual(
      expect.arrayContaining(['request', 'payload', 'nextPayload']),
    );
    expect([...state.sqlInterpolatedIdentifiers]).toEqual(
      expect.arrayContaining(['query', 'nextQuery']),
    );
    expect(state.taintedIdentifiers.has('safe')).toBe(false);
  });
});
