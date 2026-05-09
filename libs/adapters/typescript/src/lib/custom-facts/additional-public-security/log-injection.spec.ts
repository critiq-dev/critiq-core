import { parse } from '@typescript-eslint/typescript-estree';

import { collectRequestDerivedNames } from './analysis';
import { collectLogInjectionFacts } from './log-injection';
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

function collect(sourceText: string) {
  const context = createContext(sourceText);
  const taintedNames = collectRequestDerivedNames(context);

  return collectLogInjectionFacts(context, taintedNames);
}

describe('collectLogInjectionFacts', () => {
  it('flags request-controlled values interpolated into pino, winston, bunyan, and consola messages', () => {
    const facts = collect(
      [
        'function handler(req) {',
        '  const search = req.query.q;',
        '  pino.info(`search performed: ${search}`);',
        '  winston.warn(`user search: ${req.query.q}`);',
        '  winston.log("info", `tenant search: ${req.body.tenant}`);',
        '  bunyan.error("login failed for " + req.body.username);',
        '  consola.debug(`callback url ${req.query.return_to}`);',
        '}',
      ].join('\n'),
    );

    expect(facts).toHaveLength(5);
    expect(facts.map((fact) => fact.props['sink'])).toEqual(
      expect.arrayContaining([
        'pino.info',
        'winston.warn',
        'winston.log',
        'bunyan.error',
        'consola.debug',
      ]),
    );
  });

  it('does not duplicate console/logger sinks already covered by the format-string rule', () => {
    const facts = collect(
      [
        'function handler(req) {',
        '  const search = req.query.q;',
        '  console.error(`search failed: ${search}`);',
        '  logger.warn(`user search: ${req.query.q}`);',
        '  log.info("login: " + req.body.username);',
        '}',
      ].join('\n'),
    );

    expect(facts).toHaveLength(0);
  });

  it('skips sanitized payloads and structured logging objects', () => {
    const facts = collect(
      [
        'function handler(req) {',
        '  const search = req.query.q;',
        '  pino.info(`search: ${JSON.stringify(search)}`);',
        '  winston.warn(`encoded: ${encodeURIComponent(req.query.q)}`);',
        '  bunyan.info(`stripped: ${req.body.note.replace(/[\\r\\n]/g, " ")}`);',
        '  consola.warn({ search });',
        '  pino.info({ msg: "search", search });',
        '}',
      ].join('\n'),
    );

    expect(facts).toHaveLength(0);
  });

  it('flags concatenated tainted strings on broader logger sinks', () => {
    const facts = collect(
      [
        'function handler(req) {',
        '  pino.warn("user: " + req.body.username + " logged in");',
        '}',
      ].join('\n'),
    );

    expect(facts).toHaveLength(1);
    expect(facts[0].props['sink']).toBe('pino.warn');
  });

  it('ignores log calls with only constant or non-tainted interpolations', () => {
    const facts = collect(
      [
        'function handler() {',
        '  const tenant = "acme";',
        '  pino.info(`tenant ${tenant} ready`);',
        '  winston.warn(`uptime: ${process.uptime()}`);',
        '}',
      ].join('\n'),
    );

    expect(facts).toHaveLength(0);
  });
});
