import { parse } from '@typescript-eslint/typescript-estree';

import { collectOpenRedirectFacts } from './open-redirect';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    path: 'src/example.ts',
    program: parse(sourceText, {
      comment: false,
      errorOnUnknownASTType: false,
      jsx: false,
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    }),
    sourceText,
    nodeIds: new WeakMap<object, string>(),
  };
}

describe('collectOpenRedirectFacts', () => {
  it('flags direct redirect sinks fed by request-controlled values', () => {
    const facts = collectOpenRedirectFacts(
      createContext([
        'function handleLogin(req: { query: { next?: string } }, res: { redirect(value: string): void }) {',
        '  res.redirect(req.query.next ?? "/dashboard");',
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(1);
    expect(facts[0]).toEqual(
      expect.objectContaining({
        kind: 'security.open-redirect',
        appliesTo: 'block',
        props: expect.objectContaining({
          sink: 'res.redirect',
        }),
      }),
    );
  });

  it('flags router and location sinks when redirect targets come from query values', () => {
    const facts = collectOpenRedirectFacts(
      createContext([
        'function handleClient(router: { push(value: string): void }, location: { href: string }) {',
        '  const next = request.query.returnTo;',
        '  router.push(next);',
        '  location.href = next;',
        '}',
        'declare const request: { query: { returnTo?: string } };',
      ].join('\n')),
    );

    expect(facts.map((fact) => fact.props['sink']).sort()).toEqual([
      'location.href',
      'router.push',
    ]);
  });

  it('ignores internal-path normalization wrappers', () => {
    const facts = collectOpenRedirectFacts(
      createContext([
        'function safeRedirect(req: { query: { next?: string } }, res: { redirect(value: string): void }) {',
        '  const target = normalizeRedirectPath(req.query.next);',
        '  res.redirect(target);',
        '}',
        '',
        'function normalizeRedirectPath(value: string | undefined) {',
        '  return value?.startsWith("/") ? value : "/home";',
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });

  it('ignores centralized safe redirect helpers from the shared registry', () => {
    const facts = collectOpenRedirectFacts(
      createContext([
        'function safeRedirect(req: { query: { next?: string } }, res: { redirect(value: string): void }) {',
        '  res.redirect(sanitizeRedirectTarget(req.query.next));',
        '  window.location.href = toInternalPath(req.query.next);',
        '}',
        'declare function sanitizeRedirectTarget(value: string | undefined): string;',
        'declare function toInternalPath(value: string | undefined): string;',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
