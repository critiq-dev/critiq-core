import { parse } from '@typescript-eslint/typescript-estree';

import { detectReactNextBestPracticesFacts } from './react-next-best-practices';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(path: string, sourceText: string): TypeScriptFactDetectorContext {
  return {
    path,
    program: parse(sourceText, {
      comment: false,
      errorOnUnknownASTType: false,
      jsx: true,
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    }),
    sourceText,
    nodeIds: new WeakMap<object, string>(),
  };
}

describe('detectReactNextBestPracticesFacts', () => {
  it('flags cascaded fetches inside a React effect', () => {
    const context = createContext(
      'src/components/profile.tsx',
      [
        "import { useEffect } from 'react';",
        '',
        'export function Profile() {',
        '  useEffect(() => {',
        '    const load = async () => {',
        '      const user = await fetch("/api/user");',
        '      const posts = await fetch(`/api/posts?user=${user.id}`);',
        '      return { user, posts };',
        '    };',
        '',
        '    void load();',
        '  }, []);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    const facts = detectReactNextBestPracticesFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'performance.react-effect-fetch-waterfall',
          appliesTo: 'function',
          props: expect.objectContaining({
            effectHook: 'useEffect',
            fetchCount: 2,
          }),
        }),
      ]),
    );
  });

  it('flags browser-only APIs in Next server files without a client boundary', () => {
    const context = createContext(
      'src/app/page.tsx',
      [
        'export default function Page() {',
        '  return <button onClick={() => window.location.reload()}>Reload</button>;',
        '}',
      ].join('\n'),
    );

    const facts = detectReactNextBestPracticesFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'framework.next-server-client-boundary-leak',
          appliesTo: 'file',
          props: expect.objectContaining({
            filePath: 'src/app/page.tsx',
          }),
        }),
      ]),
    );
  });

  it('ignores client files with the same APIs', () => {
    const context = createContext(
      'src/app/page.tsx',
      [
        "'use client';",
        '',
        'export default function Page() {',
        '  return <button onClick={() => window.location.reload()}>Reload</button>;',
        '}',
      ].join('\n'),
    );

    expect(detectReactNextBestPracticesFacts(context)).toEqual([]);
  });
});

