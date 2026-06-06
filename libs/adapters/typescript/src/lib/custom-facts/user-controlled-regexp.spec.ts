import { parse } from '@typescript-eslint/typescript-estree';

import { collectUserControlledRegexpFacts } from './user-controlled-regexp';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    path: 'src/handler.ts',
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

describe('collectUserControlledRegexpFacts', () => {
  it('flags request-controlled RegExp construction', () => {
    const facts = collectUserControlledRegexpFacts(
      createContext([
        'export function search(req, res) {',
        '  const pattern = req.query.pattern;',
        '  const matcher = new RegExp(pattern);',
        '  const fallback = new RegExp("^safe$");',
        '  return matcher.test(req.body.value);',
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('security.user-controlled-regexp');
  });

  it('ignores static regex compilation and loop-local builders', () => {
    const facts = collectUserControlledRegexpFacts(
      createContext([
        'export function buildMatchers(items: string[]) {',
        '  const matchers = [];',
        '  for (const item of items) {',
        '    matchers.push(new RegExp(item));',
        '  }',
        '  return matchers;',
        '}',
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
