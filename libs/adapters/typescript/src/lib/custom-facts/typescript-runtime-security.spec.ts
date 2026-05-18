import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptRuntimeSecurityFacts } from './typescript-runtime-security';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(
  sourceText: string,
  path = 'src/example.ts',
): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path,
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

function kindsFor(sourceText: string): string[] {
  return collectTypescriptRuntimeSecurityFacts(createContext(sourceText)).map(
    (fact) => fact.kind,
  );
}

describe('collectTypescriptRuntimeSecurityFacts', () => {
  it('flags with statements', () => {
    expect(
      kindsFor(
        [
          'function run(ctx: Record<string, unknown>) {',
          '  with (ctx) {',
          '    value = 1;',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).toContain('security.with-statement');
  });

  it('flags arguments.callee and arguments.caller', () => {
    const kinds = kindsFor(
      [
        'function legacy() {',
        '  return arguments.callee;',
        '}',
        'function other() {',
        '  return arguments.caller;',
        '}',
      ].join('\n'),
    );

    expect(kinds.filter((kind) => kind === 'security.arguments-callee-or-caller'))
      .toHaveLength(2);
  });

  it('flags javascript: URLs in literals, templates, and JSX href', () => {
    const kinds = collectTypescriptRuntimeSecurityFacts(
      createContext(
        [
          'const href = "javascript:alert(1)";',
          'const dynamic = `javascript:${code}`;',
          'export const Link = () => <a href="javascript:void(0)">x</a>;',
        ].join('\n'),
        'src/example.tsx',
      ),
    ).map((fact) => fact.kind);

    expect(kinds.filter((kind) => kind === 'security.javascript-url').length).toBeGreaterThanOrEqual(3);
  });

  it('flags native prototype extension assignments', () => {
    expect(
      kindsFor('Array.prototype.customSort = function customSort() { return 0; };'),
    ).toContain('security.native-prototype-extension');
  });

  it('flags reassignment of global native bindings', () => {
    expect(kindsFor('undefined = 1;')).toContain(
      'security.global-native-reassignment',
    );
    expect(kindsFor('Object = {} as typeof Object;')).toContain(
      'security.global-native-reassignment',
    );
  });

  it('flags non-Error throw values', () => {
    const kinds = kindsFor(
      [
        'function fail() {',
        '  throw "boom";',
        '  throw 404;',
        '  throw new Error("ok");',
        '}',
      ].join('\n'),
    );

    expect(kinds.filter((kind) => kind === 'security.throw-literal')).toHaveLength(2);
  });

  it('flags alert, confirm, and prompt calls', () => {
    const kinds = kindsFor(
      [
        'alert("hi");',
        'window.confirm("continue?");',
        'globalThis.prompt("name");',
      ].join('\n'),
    );

    expect(kinds.filter((kind) => kind === 'security.alert-confirm-prompt')).toHaveLength(3);
  });

  it('flags process.exit calls', () => {
    expect(
      kindsFor(
        [
          'function shutdown(code: number) {',
          '  process.exit(code);',
          '}',
        ].join('\n'),
      ),
    ).toContain('runtime.process-exit');
  });

  it('flags __dirname and __filename path concatenation', () => {
    const kinds = kindsFor(
      [
        'const joined = __dirname + "/assets";',
        'const templated = `${__filename}.map`;',
      ].join('\n'),
    );

    expect(
      kinds.filter((kind) => kind === 'security.unsafe-dirname-path-concat'),
    ).toHaveLength(2);
  });

  it('ignores safe alternatives', () => {
    const kinds = kindsFor(
      [
        'const safe = "https://example.com";',
        'throw new TypeError("nope");',
        'console.log("ready");',
        'path.join(__dirname, "assets");',
      ].join('\n'),
    );

    expect(kinds).toEqual([]);
  });
});
