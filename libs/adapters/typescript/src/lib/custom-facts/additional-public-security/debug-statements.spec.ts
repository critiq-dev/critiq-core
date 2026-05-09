import { parse } from '@typescript-eslint/typescript-estree';

import { collectDebugStatementInSourceFacts } from './debug-statements';
import type { TypeScriptFactDetectorContext } from '../shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/example.ts',
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
  };
}

describe('collectDebugStatementInSourceFacts', () => {
  it('flags console.trace calls in production paths', () => {
    const facts = collectDebugStatementInSourceFacts(
      createContext(
        [
          'function handler() {',
          '  doWork();',
          '  console.trace();',
          '  console.trace("checkpoint");',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.props['statement'])).toEqual([
      'console.trace',
      'console.trace',
    ]);
  });

  it('skips dev-only branches via NODE_ENV, import.meta.env.DEV, and __DEV__ guards', () => {
    const facts = collectDebugStatementInSourceFacts(
      createContext(
        [
          'function handler() {',
          '  if (process.env.NODE_ENV !== "production") {',
          '    console.trace();',
          '  }',
          '  if (process.env.NODE_ENV === "development") {',
          '    console.trace();',
          '  }',
          '  import.meta.env.DEV && console.trace("dev");',
          '  __DEV__ && console.trace("rn");',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });

  it('does not flag other console methods, debugger statements, or unrelated identifiers', () => {
    const facts = collectDebugStatementInSourceFacts(
      createContext(
        [
          'console.log("ready");',
          'console.error("oops");',
          'logger.trace("noop");',
          'debugger;',
          'function trace() { return 1; }',
          'trace();',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });
});
