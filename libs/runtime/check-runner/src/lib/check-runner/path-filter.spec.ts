import { createPathIgnoreFilter } from './path-filter';

describe('createPathIgnoreFilter', () => {
  it('ignores node_modules and dist via fast path', () => {
    const filter = createPathIgnoreFilter(false, []);

    expect(filter.shouldIgnore('src/node_modules/pkg/index.js')).toBe(true);
    expect(filter.shouldIgnore('dist/bundle.js')).toBe(true);
    expect(filter.shouldIgnore('src/app.ts')).toBe(false);
  });

  it('excludes test files when includeTests is false', () => {
    const filter = createPathIgnoreFilter(false, []);

    expect(filter.shouldIgnore('src/foo.test.ts')).toBe(true);
    expect(filter.shouldIgnore('src/__tests__/foo.ts')).toBe(true);
    expect(filter.shouldIgnore('src/app.ts')).toBe(false);
  });

  it('includes test files when includeTests is true', () => {
    const filter = createPathIgnoreFilter(true, []);

    expect(filter.shouldIgnore('src/foo.test.ts')).toBe(false);
    expect(filter.shouldIgnore('src/__tests__/foo.ts')).toBe(false);
  });

  it('honors user ignore paths', () => {
    const filter = createPathIgnoreFilter(false, ['**/generated/**']);

    expect(filter.shouldIgnore('src/generated/output.ts')).toBe(true);
  });

  it('ignores .venv-prefixed directories', () => {
    const filter = createPathIgnoreFilter(false, []);

    expect(
      filter.shouldIgnore('.venv-cfn-lint/lib/python3.14/site-packages/foo.py'),
    ).toBe(true);
    expect(filter.shouldIgnore('src/__pycache__/module.pyc')).toBe(true);
  });
});
