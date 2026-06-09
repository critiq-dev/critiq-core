import { parseSql, isSqlKeyword } from './parse';

describe('parseSql', () => {
  it('parses a simple SELECT', () => {
    const result = parseSql('SELECT * FROM users');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(Array.isArray(result.ast) ? result.ast[0] : result.ast).toMatchObject({
        type: 'select',
      });
    }
  });

  it('parses SELECT with WHERE clause', () => {
    const result = parseSql("SELECT id, name FROM users WHERE age > 21");
    expect(result.success).toBe(true);
  });

  it('parses JOIN query', () => {
    const result = parseSql(
      'SELECT u.id, o.total FROM users AS u INNER JOIN orders AS o ON u.id = o.user_id'
    );
    expect(result.success).toBe(true);
  });

  it('parses INSERT statement', () => {
    const result = parseSql("INSERT INTO users (name, age) VALUES ('Alice', 30)");
    expect(result.success).toBe(true);
  });

  it('parses UPDATE statement', () => {
    const result = parseSql("UPDATE users SET name = 'Bob' WHERE id = 1");
    expect(result.success).toBe(true);
  });

  it('parses DELETE statement', () => {
    const result = parseSql('DELETE FROM users WHERE id = 1');
    expect(result.success).toBe(true);
  });

  it('handles empty input', () => {
    const result = parseSql('');
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain('Empty');
    }
  });

  it('handles whitespace-only input', () => {
    const result = parseSql('   ');
    expect(result.success).toBe(false);
  });

  it('rejects completely invalid SQL', () => {
    const result = parseSql('NOT VALID SQL AT ALL');
    expect(result.success).toBe(false);
  });
});

describe('isSqlKeyword', () => {
  it('returns true for SQL keywords', () => {
    expect(isSqlKeyword('SELECT')).toBe(true);
    expect(isSqlKeyword('from')).toBe(true);
    expect(isSqlKeyword('Where')).toBe(true);
    expect(isSqlKeyword('AND')).toBe(true);
  });

  it('returns false for non-keywords', () => {
    expect(isSqlKeyword('users')).toBe(false);
    expect(isSqlKeyword('my_table')).toBe(false);
    expect(isSqlKeyword('')).toBe(false);
  });
});
