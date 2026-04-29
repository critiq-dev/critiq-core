import { parse } from '@typescript-eslint/typescript-estree';

import { collectQueryCommandDynamicExecutionFacts } from './query-command-dynamic-execution';
import { type TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/query-command-dynamic-execution.ts',
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

describe('collectQueryCommandDynamicExecutionFacts', () => {
  it('flags interpolated and request-driven SQL sinks', () => {
    const facts = collectQueryCommandDynamicExecutionFacts(
      createContext([
        'async function handler(req, db, prisma) {',
        '  const where = req.query.whereClause;',
        "  const sql = `SELECT * FROM users WHERE email = '${where}'`;",
        '  await db.query(sql);',
        "  await prisma.raw('SELECT * FROM users WHERE id = ' + req.query.id);",
        '  await prisma.$queryRawUnsafe(req.body.queryText);',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.sql-interpolation'),
    ).toHaveLength(3);
  });

  it('flags request-controlled command execution and dynamic execution sinks', () => {
    const facts = collectQueryCommandDynamicExecutionFacts(
      createContext([
        "import vm from 'node:vm';",
        'function run(req) {',
        '  exec(req.query.cmd);',
        "  spawn('/usr/bin/env', [req.body.task], { shell: true });",
        '  vm.runInNewContext(req.body.source, {});',
        "  setTimeout('doWork()', 25);",
        '}',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.command-execution-with-request-input',
        }),
        expect.objectContaining({
          kind: 'security.command-execution-with-request-input',
        }),
        expect.objectContaining({
          kind: 'security.dynamic-execution',
        }),
        expect.objectContaining({
          kind: 'security.dynamic-execution',
        }),
      ]),
    );
  });

  it('ignores parameterized SQL, allowlisted spawn calls, and function timers', () => {
    const facts = collectQueryCommandDynamicExecutionFacts(
      createContext([
        'const COMMANDS = {',
        "  healthcheck: ['/usr/bin/env', 'uptime'],",
        '} as const;',
        '',
        'function later() {',
        "  return 'ok';",
        '}',
        '',
        'async function run(email, db, childProcess) {',
        "  const query = 'SELECT * FROM users WHERE email = $1';",
        '  await db.execute(query, [email]);',
        "  childProcess.spawn('/usr/bin/env', ['uptime']);",
        '  setTimeout(later, 25);',
        '}',
      ].join('\n')),
    );

    expect(facts).toEqual([]);
  });
});
