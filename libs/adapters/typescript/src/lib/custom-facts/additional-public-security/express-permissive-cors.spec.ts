import { parse } from '@typescript-eslint/typescript-estree';

import { collectExpressPermissiveCorsFacts } from './express-permissive-cors';
import { type TypeScriptFactDetectorContext } from '../shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/app.ts',
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

describe('collectExpressPermissiveCorsFacts', () => {
  it('flags permissive origins when credentials are enabled', () => {
    const facts = collectExpressPermissiveCorsFacts(
      createContext([
        'app.use(cors({ origin: true, credentials: true }));',
        'app.use(cors({ origin: "*", credentials: true }));',
        'app.use(cors({ credentials: true }));',
      ].join('\n')),
    );

    expect(facts).toHaveLength(3);
    expect(facts.every((fact) => fact.kind === 'security.express-permissive-cors')).toBe(
      true,
    );
  });

  it('ignores permissive origins without credentials and explicit allowlists', () => {
    const facts = collectExpressPermissiveCorsFacts(
      createContext([
        'app.use(cors({ origin: true }));',
        'app.use(cors({ origin: ["https://app.example.com"], credentials: true }));',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
