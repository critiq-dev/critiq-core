import { parse } from '@typescript-eslint/typescript-estree';

import { collectInsecureTransportFacts } from './insecure-transport';

function analyze(text: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectInsecureTransportFacts({
    nodeIds: new WeakMap(),
    path: 'src/example.ts',
    program,
    sourceText: text,
  });
}

describe('collectInsecureTransportFacts', () => {
  it('flags disabled tls verification and plain http transport', () => {
    const facts = analyze(
      [
        'import https from "node:https";',
        '',
        'const agent = new https.Agent({ rejectUnauthorized: false });',
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
        'fetch("http://example.com/api");',
        'fetch("http://localhost:3000/health");',
      ].join('\n'),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.tls-verification-disabled',
          appliesTo: 'block',
          props: expect.objectContaining({
            option: 'rejectUnauthorized',
            sink: 'tls-agent',
            value: false,
          }),
        }),
        expect.objectContaining({
          kind: 'security.tls-verification-disabled',
          appliesTo: 'block',
          props: expect.objectContaining({
            option: 'NODE_TLS_REJECT_UNAUTHORIZED',
            sink: 'process.env',
            value: '0',
          }),
        }),
        expect.objectContaining({
          kind: 'security.insecure-http-transport',
          appliesTo: 'block',
          props: expect.objectContaining({
            sink: 'fetch',
            url: 'http://example.com/api',
          }),
        }),
      ]),
    );

    expect(facts).toHaveLength(3);
  });

  it('ignores local development http urls and secure transport', () => {
    const facts = analyze(
      [
        'fetch("https://example.com/api");',
        'axios.get("http://localhost:3000/api");',
        'const agent = { rejectUnauthorized: true };',
      ].join('\n'),
    );

    expect(facts).toEqual([]);
  });
});

