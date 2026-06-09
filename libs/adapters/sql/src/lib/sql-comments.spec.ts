import { findSqlCommentRanges, isInCommentRange, stripSqlComments } from './sql-comments';

describe('findSqlCommentRanges', () => {
  it('finds single-line comments', () => {
    const sql = 'SELECT * FROM users -- comment\nWHERE id = 1';
    const ranges = findSqlCommentRanges(sql);
    expect(ranges).toHaveLength(1);
    expect(ranges[0]!.startOffset).toBe(sql.indexOf('-- comment'));
    expect(ranges[0]!.endOffset).toBe(sql.indexOf('\n'));
  });

  it('finds multi-line comments', () => {
    const sql = 'SELECT * /* block comment */ FROM users';
    const ranges = findSqlCommentRanges(sql);
    expect(ranges).toHaveLength(1);
    expect(ranges[0]!.startOffset).toBe(sql.indexOf('/*'));
    expect(ranges[0]!.endOffset).toBe(sql.indexOf('*/') + 2);
  });

  it('finds comment at end of file without newline', () => {
    const sql = 'SELECT * FROM users -- trailing comment';
    const ranges = findSqlCommentRanges(sql);
    expect(ranges).toHaveLength(1);
    expect(ranges[0]!.endOffset).toBe(sql.length);
  });

  it('finds multiple comments', () => {
    const sql = '-- first\nSELECT *\n-- second\nFROM users';
    const ranges = findSqlCommentRanges(sql);
    expect(ranges).toHaveLength(2);
  });

  it('returns empty for no comments', () => {
    const sql = 'SELECT * FROM users';
    const ranges = findSqlCommentRanges(sql);
    expect(ranges).toHaveLength(0);
  });
});

describe('isInCommentRange', () => {
  it('returns true for offset inside a comment', () => {
    const sql = 'SELECT * -- comment here\nFROM users';
    const ranges = findSqlCommentRanges(sql);
    const commentOffset = sql.indexOf('comment');
    expect(isInCommentRange(commentOffset, ranges)).toBe(true);
  });

  it('returns false for offset outside comments', () => {
    const sql = 'SELECT * -- comment\nFROM users';
    const ranges = findSqlCommentRanges(sql);
    const selectOffset = sql.indexOf('SELECT');
    expect(isInCommentRange(selectOffset, ranges)).toBe(false);
  });
});

describe('stripSqlComments', () => {
  it('removes single-line comments', () => {
    const sql = 'SELECT * FROM users -- comment\nWHERE id = 1';
    expect(stripSqlComments(sql)).toBe('SELECT * FROM users \nWHERE id = 1');
  });

  it('removes multi-line comments', () => {
    const sql = 'SELECT * /* block */ FROM users';
    expect(stripSqlComments(sql)).toBe('SELECT *  FROM users');
  });

  it('returns text unchanged when no comments', () => {
    const sql = 'SELECT * FROM users';
    expect(stripSqlComments(sql)).toBe('SELECT * FROM users');
  });
});
