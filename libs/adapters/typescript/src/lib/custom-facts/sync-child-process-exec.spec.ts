import { parse } from '@typescript-eslint/typescript-estree';

import { collectSyncChildProcessExecFacts } from './sync-child-process-exec';
import { type TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/worker.ts',
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

describe('collectSyncChildProcessExecFacts', () => {
  it('flags sync process calls with dynamic command strings', () => {
    const facts = collectSyncChildProcessExecFacts(
      createContext([
        'import { execSync, spawnSync } from "node:child_process";',
        'const command = process.env.CMD ?? "uptime";',
        'execSync(command);',
        'spawnSync(`ls ${command}`);',
      ].join('\n')),
    );

    expect(facts).toHaveLength(2);
    expect(
      facts.every((fact) => fact.kind === 'security.sync-child-process-exec'),
    ).toBe(true);
  });

  it('ignores static command strings', () => {
    const facts = collectSyncChildProcessExecFacts(
      createContext('execSync("uptime");'),
    );

    expect(facts).toHaveLength(0);
  });
});
