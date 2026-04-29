import { parse } from '@typescript-eslint/typescript-estree';

import { collectNetworkExposureFacts } from './network-exposure';
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

describe('collectNetworkExposureFacts', () => {
  it('flags explicit all-interface bind targets across common server entrypoints', () => {
    const facts = collectNetworkExposureFacts(
      createContext([
        'app.listen(3000, "0.0.0.0");',
        'server.listen({ port: 3001, host: "::" });',
        'Deno.serve({ hostname: "0.0.0.0", port: 8000 }, handler);',
        'Bun.serve({ hostname: "::", port: 3000, fetch() { return new Response("ok"); } });',
        'new WebSocketServer({ host: "0.0.0.0", port: 8080 });',
      ].join('\n')),
    );

    expect(facts).toHaveLength(5);
    expect(facts.map((fact) => fact.props['sink'])).toEqual([
      'app.listen',
      'server.listen',
      'Deno.serve',
      'Bun.serve',
      'WebSocketServer',
    ]);
  });

  it('ignores omitted-host defaults and loopback-only binds', () => {
    const facts = collectNetworkExposureFacts(
      createContext([
        'app.listen(3000);',
        'app.listen(3000, "127.0.0.1");',
        'server.listen({ port: 3001, host: "localhost" });',
        'Deno.serve({ hostname: "127.0.0.1", port: 8000 }, handler);',
        'Bun.serve({ hostname: "localhost", port: 3000, fetch() { return new Response("ok"); } });',
        'new WebSocketServer({ host: "127.0.0.1", port: 8080 });',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
