import { parse } from '@typescript-eslint/typescript-estree';

import { collectInsecureServerListenFacts } from './insecure-server-listen';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    path: 'src/server.ts',
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

describe('collectInsecureServerListenFacts', () => {
  it('flags plain HTTP server bootstrap and public framework listens', () => {
    const facts = collectInsecureServerListenFacts(
      createContext([
        "const express = require('express');",
        'const app = express();',
        "app.listen(3000, '0.0.0.0');",
        "const server = http.createServer(app);",
      ].join('\n')),
    );

    expect(facts).toHaveLength(2);
    expect(facts.every((fact) => fact.kind === 'security.express-insecure-listen')).toBe(
      true,
    );
  });

  it('ignores HTTPS bootstrap, TLS termination guards, and loopback-only listens', () => {
    expect(
      collectInsecureServerListenFacts(
        createContext([
          "const https = require('https');",
          'https.createServer(credentials, app).listen(443);',
        ].join('\n')),
      ),
    ).toHaveLength(0);

    expect(
      collectInsecureServerListenFacts(
        createContext([
          'const app = express();',
          'app.set("trust proxy", 1);',
          "app.listen(3000, '0.0.0.0');",
        ].join('\n')),
      ),
    ).toHaveLength(0);

    expect(
      collectInsecureServerListenFacts(
        createContext([
          'export function listenLocally(app) {',
          "  app.listen(3000, '127.0.0.1');",
          '  app.listen(3001);',
          '}',
        ].join('\n')),
      ),
    ).toHaveLength(0);
  });

  it('ignores dev-only listen blocks', () => {
    const facts = collectInsecureServerListenFacts(
      createContext([
        'const app = express();',
        'if (process.env.NODE_ENV !== "production") {',
        "  app.listen(3000, '0.0.0.0');",
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
