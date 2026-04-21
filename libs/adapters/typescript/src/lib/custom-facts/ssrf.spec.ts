import { parse, type TSESTree } from '@typescript-eslint/typescript-estree';

import { collectSsrfFacts } from './ssrf';
import { walkAst, type TypeScriptFactDetectorContext } from './shared';

function buildNodeIds(program: TSESTree.Program): WeakMap<object, string> {
  const nodeIds = new WeakMap<object, string>();
  let index = 0;

  walkAst(program, (node) => {
    nodeIds.set(node as unknown as object, `node-${index}`);
    index += 1;
  });

  return nodeIds;
}

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  const program = parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return {
    nodeIds: buildNodeIds(program),
    path: 'src/example.ts',
    program,
    sourceText,
  };
}

describe('collectSsrfFacts', () => {
  it('flags request-controlled outbound targets and private host literals', () => {
    const facts = collectSsrfFacts(
      createContext(
        [
          'declare const req: { query: { url: string }, body: { host: string } };',
          'declare const http: { request(value: unknown): void };',
          'declare const got: (value: unknown) => void;',
          '',
          'const target = req.query.url;',
          'fetch(target);',
          'got(req.body.url);',
          'http.request({ hostname: "169.254.169.254", path: "/latest/meta-data" });',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(3);
    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.ssrf',
          appliesTo: 'block',
          props: expect.objectContaining({
            sink: 'fetch',
            reason: 'request-controlled-target',
          }),
        }),
        expect.objectContaining({
          kind: 'security.ssrf',
          appliesTo: 'block',
          props: expect.objectContaining({
            sink: 'got',
            reason: 'request-controlled-target',
          }),
        }),
        expect.objectContaining({
          kind: 'security.ssrf',
          appliesTo: 'block',
          props: expect.objectContaining({
            sink: 'http.request',
            reason: 'private-host',
          }),
        }),
      ]),
    );
  });

  it('ignores safe url wrappers and ordinary public targets', () => {
    const facts = collectSsrfFacts(
      createContext(
        [
          'declare const req: { query: { url: string } };',
          'declare function normalizeAllowedUrl(value: string): string;',
          'declare function assertAllowedHost(value: string): string;',
          '',
          'fetch(normalizeAllowedUrl(req.query.url));',
          'fetch(assertAllowedHost("https://example.com/api"));',
          'got("https://example.com/api");',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });
});

