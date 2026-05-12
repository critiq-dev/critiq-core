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

  it('flags fetch-driven effects that never cancel inflight requests', () => {
    const context = createContext(
      'src/components/user-card.tsx',
      [
        "import { useEffect, useState } from 'react';",
        '',
        'export function UserCard({ userId }: { userId: string }) {',
        '  const [user, setUser] = useState<User | null>(null);',
        '',
        '  useEffect(() => {',
        '    fetch(`/api/users/${userId}`)',
        '      .then((res) => res.json())',
        '      .then(setUser);',
        '  }, [userId]);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(detectReactNextBestPracticesFacts(context)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'performance.react-effect-fetch-without-cancellation',
        }),
      ]),
    );
  });

  it('flags Apollo-style client.query chains that hydrate state without AbortSignal', () => {
    const context = createContext(
      'src/components/gql-user-card.tsx',
      [
        "import { useEffect, useState } from 'react';",
        '',
        'declare const apolloClient: { query: (opts: unknown) => Promise<{ data: { u: unknown } }> };',
        '',
        'export function GqlUserCard({ id }: { id: string }) {',
        '  const [user, setUser] = useState<unknown>(null);',
        '',
        '  useEffect(() => {',
        '    apolloClient',
        '      .query({ query: {}, variables: { id } })',
        '      .then((r) => setUser(r.data.u));',
        '  }, [id]);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(detectReactNextBestPracticesFacts(context)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'performance.react-effect-fetch-without-cancellation',
        }),
      ]),
    );
  });

  it('ignores effects guarded with a cancelled flag before committing state', () => {
    const context = createContext(
      'src/components/user-card.tsx',
      [
        "import { useEffect, useState } from 'react';",
        '',
        'export function UserCard({ userId }: { userId: string }) {',
        '  const [user, setUser] = useState<User | null>(null);',
        '',
        '  useEffect(() => {',
        '    let cancelled = false;',
        '',
        '    fetch(`/api/users/${userId}`)',
        '      .then((res) => res.json())',
        '      .then((data) => {',
        '        if (!cancelled) {',
        '          setUser(data);',
        '        }',
        '      });',
        '',
        '    return () => {',
        '      cancelled = true;',
        '    };',
        '  }, [userId]);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactNextBestPracticesFacts(context).filter(
        (fact) => fact.kind === 'performance.react-effect-fetch-without-cancellation',
      ),
    ).toHaveLength(0);
  });

  it('ignores fetch effects when the component uses route loader data', () => {
    const context = createContext(
      'src/routes/user.tsx',
      [
        "import { useEffect, useState } from 'react';",
        "import { useLoaderData } from 'react-router-dom';",
        '',
        'type User = { id: string };',
        '',
        'export function UserRoute() {',
        '  const route = useLoaderData() as { userId: string };',
        '  const [user, setUser] = useState<User | null>(null);',
        '',
        '  useEffect(() => {',
        '    fetch(`/api/users/${route.userId}`)',
        '      .then((res) => res.json())',
        '      .then(setUser);',
        '  }, [route.userId]);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactNextBestPracticesFacts(context).filter(
        (fact) => fact.kind === 'performance.react-effect-fetch-without-cancellation',
      ),
    ).toHaveLength(0);
  });

  it('ignores effects that abort fetch when dependencies change', () => {
    const context = createContext(
      'src/components/user-card.tsx',
      [
        "import { useEffect, useState } from 'react';",
        '',
        'export function UserCard({ userId }: { userId: string }) {',
        '  const [user, setUser] = useState<User | null>(null);',
        '',
        '  useEffect(() => {',
        '    const controller = new AbortController();',
        '',
        '    fetch(`/api/users/${userId}`, { signal: controller.signal })',
        '      .then((res) => res.json())',
        '      .then(setUser);',
        '',
        '    return () => controller.abort();',
        '  }, [userId]);',
        '',
        '  return null;',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactNextBestPracticesFacts(context).filter(
        (fact) => fact.kind === 'performance.react-effect-fetch-without-cancellation',
      ),
    ).toHaveLength(0);
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

