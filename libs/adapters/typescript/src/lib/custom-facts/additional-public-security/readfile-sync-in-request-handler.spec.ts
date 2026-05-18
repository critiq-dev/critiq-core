import { parse } from '@typescript-eslint/typescript-estree';

import { collectReadFileSyncInRequestHandlerFacts } from './readfile-sync-in-request-handler';
import { type TypeScriptFactDetectorContext } from '../shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/routes.ts',
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
  };
}

describe('collectReadFileSyncInRequestHandlerFacts', () => {
  it('flags blocking file reads inside request handlers', () => {
    const facts = collectReadFileSyncInRequestHandlerFacts(
      createContext([
        'import { readFileSync } from "node:fs";',
        'function handler(req, res) {',
        '  const body = readFileSync("./template.html", "utf8");',
        '  res.send(body);',
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('security.readfile-sync-in-request-handler');
  });

  it('ignores sync reads outside request handlers', () => {
    const facts = collectReadFileSyncInRequestHandlerFacts(
      createContext('readFileSync("./config.json", "utf8");'),
    );

    expect(facts).toHaveLength(0);
  });
});
