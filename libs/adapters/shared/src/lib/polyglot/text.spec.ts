import { hasRemotePlainHttpUrl, stripHashLineComment } from './text';

describe('polyglot text helpers', () => {
  it('detects remote plain-http URLs and ignores localhost targets', () => {
    expect(
      hasRemotePlainHttpUrl('fetch("http://api.example.com/users")'),
    ).toBe(true);
    expect(hasRemotePlainHttpUrl('fetch("http://localhost:3000/users")')).toBe(
      false,
    );
    expect(hasRemotePlainHttpUrl('fetch("https://api.example.com/users")')).toBe(
      false,
    );
  });

  it('strips hash comments while preserving quoted values', () => {
    expect(stripHashLineComment('value = call("keep # inside") # remove')).toBe(
      'value = call("keep # inside") ',
    );
    expect(stripHashLineComment("value = 'keep # inside' # remove")).toBe(
      "value = 'keep # inside' ",
    );
  });
});
