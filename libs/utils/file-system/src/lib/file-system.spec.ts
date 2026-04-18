import { resolveWorkspacePath } from './file-system';

describe('resolveWorkspacePath', () => {
  it('resolves a path from the provided workspace root', () => {
    expect(resolveWorkspacePath('/workspace', 'docs', 'repo-map.md')).toBe(
      '/workspace/docs/repo-map.md',
    );
  });
});
