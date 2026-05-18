import { parse } from '@typescript-eslint/typescript-estree';

import { collectMutableModuleExportFacts } from './mutable-module-export';
import { type TypeScriptFactDetectorContext } from '../shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/state.ts',
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

describe('collectMutableModuleExportFacts', () => {
  it('flags export let bindings and reassigned exports', () => {
    const facts = collectMutableModuleExportFacts(
      createContext([
        'export let counter = 0;',
        'let shared = 1;',
        'export { shared };',
        'shared = 2;',
      ].join('\n')),
    );

    expect(facts.map((fact) => fact.text).sort()).toEqual(['counter', 'shared']);
    expect(
      facts.every((fact) => fact.kind === 'security.mutable-module-export'),
    ).toBe(true);
  });

  it('ignores immutable export const bindings', () => {
    const facts = collectMutableModuleExportFacts(
      createContext('export const VERSION = "1.0.0";'),
    );

    expect(facts).toHaveLength(0);
  });
});
