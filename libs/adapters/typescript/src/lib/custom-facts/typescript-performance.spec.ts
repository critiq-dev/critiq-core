import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptPerformanceFacts } from './typescript-performance';

function analyze(text: string, filePath?: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectTypescriptPerformanceFacts({
    nodeIds: new WeakMap(),
    path: filePath ?? 'src/example.ts',
    program,
    sourceText: text,
  });
}

function kindsMatching(facts: Array<{ kind: string }>, kind: string): Array<{ kind: string }> {
  return facts.filter((f) => f.kind === kind);
}

describe('no-await-in-loop detection', () => {
  it('flags await in for...of loop', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  for (const id of ids) {',
        '    await load(id);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('flags await in for loop', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  for (let i = 0; i < ids.length; i++) {',
        '    await load(ids[i]);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('flags await in while loop', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  let i = 0;',
        '  while (i < ids.length) {',
        '    await load(ids[i]);',
        '    i++;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('flags await in do-while loop', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  let i = 0;',
        '  do {',
        '    await load(ids[i]);',
        '    i++;',
        '  } while (i < ids.length);',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('suppresses new Promise(setTimeout) retry sleep', () => {
    const facts = analyze(
      [
        'export async function retry(op: () => Promise<void>, max: number, delayMs: number) {',
        '  for (let i = 1; i <= max; i++) {',
        '    try {',
        '      await op();',
        '      return;',
        '    } catch (e) {',
        '      if (i === max) throw e;',
        '      await new Promise((resolve) => setTimeout(resolve, delayMs));',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('suppresses await delay() as timer utility', () => {
    const facts = analyze(
      [
        'async function delay(ms: number) { return new Promise(r => setTimeout(r, ms)); }',
        'export async function countdown(start: number, ms: number) {',
        '  for (let i = start; i > 0; i--) {',
        '    await delay(ms);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await sleep() as timer utility', () => {
    const facts = analyze(
      [
        'async function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }',
        'export async function poll(check: () => Promise<boolean>, interval: number, max: number) {',
        '  for (let i = 0; i < max; i++) {',
        '    if (await check()) return;',
        '    await sleep(interval);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(1);
  });

  it('excludes test files from detection', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  for (const id of ids) {',
        '    await load(id);',
        '  }',
        '}',
      ].join('\n'),
      'src/__tests__/example.test.ts',
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('excludes e2e-test files from detection', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  for (const id of ids) {',
        '    await load(id);',
        '  }',
        '}',
      ].join('\n'),
      'frontend/e2e-tests/test-utils.ts',
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('allows Promise.all as valid pattern', () => {
    const facts = analyze(
      [
        'async function load(id: number) { return id; }',
        'export async function process(ids: number[]) {',
        '  await Promise.all(ids.map((id) => load(id)));',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await Promise.all inside a loop', () => {
    const facts = analyze(
      [
        'async function send(recipient: string) { return recipient; }',
        'export async function process(recipients: string[]) {',
        '  for (const r of recipients) {',
        '    await Promise.all([send(r), send(r)]);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await Promise.allSettled inside a loop', () => {
    const facts = analyze(
      [
        'async function verify(id: string) { return id; }',
        'export async function process(ids: string[]) {',
        '  for (const id of ids) {',
        '    await Promise.allSettled([verify(id)]);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await reader.read() stream pattern in loop', () => {
    const facts = analyze(
      [
        'interface Reader { read(): Promise<{ done: boolean }> }',
        'export async function process(reader: Reader) {',
        '  while (true) {',
        '    const { done } = await reader.read();',
        '    if (done) break;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await streamReader.read() pattern in loop', () => {
    const facts = analyze(
      [
        'interface StreamReader { read(): Promise<{ done: boolean }> }',
        'export async function process(streamReader: StreamReader) {',
        '  while (true) {',
        '    const { done } = await streamReader.read();',
        '    if (done) break;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await tx.method() transaction pattern in loop', () => {
    const facts = analyze(
      [
        'interface TxClient { user: { update(args: unknown): Promise<void> } }',
        'export async function process(users: { id: string }[], tx: TxClient) {',
        '  for (const user of users) {',
        '    await tx.user.update({ where: { id: user.id } });',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses await tx.nested.method() in loop', () => {
    const facts = analyze(
      [
        'interface TxClient { document: { data: { update(args: unknown): Promise<void> } } }',
        'export async function process(items: { id: string }[], tx: TxClient) {',
        '  for (const item of items) {',
        '    await tx.document.data.update({ where: { id: item.id } });',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });

  it('suppresses inner await inside .map callback passed to Promise.all', () => {
    const facts = analyze(
      [
        'async function verify(id: string) { return true; }',
        'async function reregister(id: string) {}',
        'export async function process(batches: string[][]) {',
        '  for (const batch of batches) {',
        '    await Promise.allSettled(',
        '      batch.map(async (domainId) => {',
        '        const ok = await verify(domainId);',
        '        if (!ok) return;',
        '        await reregister(domainId);',
        '      }),',
        '    );',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(kindsMatching(facts, 'performance.no-await-in-loop')).toHaveLength(0);
  });
});
