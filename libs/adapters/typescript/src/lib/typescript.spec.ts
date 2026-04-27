import { analyzeTypeScriptFile, typescriptAdapterPackageName } from './typescript';

describe('typescriptAdapterPackageName', () => {
  it('returns the expected package import path', () => {
    expect(typescriptAdapterPackageName()).toBe('@critiq/adapter-typescript');
  });
});

describe('analyzeTypeScriptFile', () => {
  it('parses TypeScript source into a deterministic analyzed file', () => {
    const result = analyzeTypeScriptFile(
      'src/example.ts',
      'console.log("hello");\n',
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('typescript');
    expect(result.data.nodes[0]).toEqual(
      expect.objectContaining({
        kind: 'Program',
      }),
    );

    const callExpression = result.data.nodes.find(
      (node) => node.kind === 'CallExpression',
    );

    expect(callExpression).toEqual(
      expect.objectContaining({
        props: expect.objectContaining({
          text: 'console.log("hello")',
          callee: {
            text: 'console.log',
            object: {
              text: 'console',
            },
            property: {
              text: 'log',
            },
          },
          argument: {
            text: '"hello"',
          },
          arguments: [
            {
              text: '"hello"',
            },
          ],
        }),
      }),
    );
    expect(result.data.semantics?.controlFlow).toEqual(
      expect.objectContaining({
        functions: expect.any(Array),
        blocks: expect.any(Array),
        edges: expect.any(Array),
        facts: expect.any(Array),
      }),
    );
  });

  it('supports javascript and jsx file extensions', () => {
    const jsResult = analyzeTypeScriptFile('src/example.js', 'debugger;\n');
    const jsxResult = analyzeTypeScriptFile(
      'src/example.jsx',
      'const node = <div>Hello</div>;\n',
    );

    expect(jsResult.success).toBe(true);
    expect(jsxResult.success).toBe(true);

    if (!jsResult.success || !jsxResult.success) {
      throw new Error('Expected analysis success.');
    }

    expect(jsResult.data.language).toBe('javascript');
    expect(jsxResult.data.language).toBe('javascript');
  });

  it('returns structured diagnostics for parser failures', () => {
    const result = analyzeTypeScriptFile('src/broken.ts', 'const = ;');

    expect(result).toEqual({
      success: false,
      diagnostics: [
        expect.objectContaining({
          code: 'typescript.parse.invalid',
          severity: 'error',
        }),
      ],
    });
  });

  it('emits control-flow facts for the shipped control-flow rule set', () => {
    const result = analyzeTypeScriptFile(
      'src/control-flow.ts',
      [
        'function alwaysTrue() {',
        '  if ("ready" === "ready") {',
        '    return 1;',
        '  }',
        '',
        '  return 0;',
        '}',
        '',
        'function wrongBoolean(status: string) {',
        '  if (status === "open" && status === "closed") {',
        '    return 1;',
        '  }',
        '',
        '  return 0;',
        '}',
        '',
        'function offByOne(values: string[]) {',
        '  for (let index = 0; index <= values.length; index++) {',
        '    console.log(values[index]);',
        '  }',
        '}',
        '',
        'function maybeValue(flag: boolean) {',
        '  if (flag) {',
        '    return "x";',
        '  }',
        '}',
        '',
        'function unreachable() {',
        '  return 1;',
        '  console.log("dead");',
        '}',
        '',
        'function swallow() {',
        '  try {',
        '    run();',
        '  } catch (error) {',
        '    logger.error("failed");',
        '  }',
        '}',
        '',
        'function missingDefault(mode: string) {',
        '  if (mode === "a") {',
        '    return 1;',
        '  } else if (mode === "b") {',
        '    return 2;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'control-flow.constant-condition',
          appliesTo: 'block',
          props: expect.objectContaining({
            constantValue: true,
          }),
        }),
        expect.objectContaining({
          kind: 'control-flow.incorrect-boolean-logic',
          appliesTo: 'block',
          props: expect.objectContaining({
            operator: '&&',
          }),
        }),
        expect.objectContaining({
          kind: 'control-flow.off-by-one-loop-boundary',
          appliesTo: 'block',
          props: expect.objectContaining({
            loopDirection: 'ascending',
          }),
        }),
        expect.objectContaining({
          kind: 'control-flow.implicit-undefined-return',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'control-flow.unreachable-statement',
          appliesTo: 'block',
          props: expect.objectContaining({
            reason: 'after-return',
          }),
        }),
        expect.objectContaining({
          kind: 'error-handling.missing-error-context',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'control-flow.missing-default-dispatch',
          appliesTo: 'block',
        }),
      ]),
    );
  });

  it('emits async and concurrency facts for the shipped async rule set', () => {
    const result = analyzeTypeScriptFile(
      'src/async.ts',
      [
        'const fs = {',
        '  readFileSync: (_path: string, _encoding: string) => "data",',
        '};',
        '',
        'async function loadProfile() {',
        '  return { id: 1 };',
        '}',
        '',
        'async function loadAudit() {',
        '  return { ok: true };',
        '}',
        '',
        'export async function missingAwait() {',
        '  loadProfile();',
        '}',
        '',
        'export function unhandledAsyncError() {',
        '  loadProfile().then((profile) => profile.id);',
        '}',
        '',
        'export async function blocking(path: string) {',
        '  return fs.readFileSync(path, "utf8");',
        '}',
        '',
        'export async function missingTimeout() {',
        '  return await fetch("/users");',
        '}',
        '',
        'let sharedCounter = 0;',
        '',
        'export async function race() {',
        '  await loadProfile();',
        '  sharedCounter += 1;',
        '  return sharedCounter;',
        '}',
        '',
        'export async function sequential() {',
        '  const profile = await loadProfile();',
        '  const audit = await loadAudit();',
        '  return { profile, audit };',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'async.missing-await',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'async.unhandled-async-error',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'async.blocking-call-in-async-flow',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'resilience.missing-timeout-on-external-call',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'concurrency.shared-state-race',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'performance.sequential-async-calls',
          appliesTo: 'block',
        }),
      ]),
    );
  });

  it('emits data-flow and taint facts for the shipped runtime rule set', () => {
    const result = analyzeTypeScriptFile(
      'src/data-flow.ts',
      [
        'declare function decode(token: string): unknown;',
        'declare const app: { get(path: string, handler: () => void): void };',
        '',
        'type Request = {',
        '  body: any;',
        '  headers: Record<string, string | undefined>;',
        '  query: Record<string, string | undefined>;',
        '};',
        '',
        'export function maybeNull(flag: boolean) {',
        '  const user = flag ? { name: "Ada" } : null;',
        '  return user.name;',
        '}',
        '',
        'export function nestedAccess(req: Request) {',
        '  const payload = req.body;',
        '  return payload.user.profile.city;',
        '}',
        '',
        'export function uncheckedLookup(cache: Map<string, string>, id: string) {',
        '  return cache.get(id);',
        '}',
        '',
        'export function safeIndexedAccess(values: string[]) {',
        '  const first = values[0];',
        '  app.get("/users", () => undefined);',
        '  return first ?? "missing";',
        '}',
        '',
        'export function optionalWithoutFallback(values: string[]) {',
        '  const match = values.find((value) => value.startsWith("a"));',
        '  return match + "!";',
        '}',
        '',
        'export function tokenWithoutValidation(req: Request) {',
        '  const token = req.headers.authorization;',
        '  return decode(token ?? "");',
        '}',
        '',
        'export function unvalidatedInput(req: Request) {',
        '  const pattern = req.query.pattern;',
        '  return new RegExp(pattern);',
        '}',
        '',
        'export function unsafeParse(req: Request) {',
        '  const raw = req.body.payload;',
        '  return JSON.parse(raw);',
        '}',
        '',
        'export async function requestWithoutTimeout() {',
        '  return await fetch("/users");',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'data-flow.possible-null-dereference',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'data-flow.nested-property-access-without-check',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'data-flow.unchecked-map-key-access',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'data-flow.optional-value-without-fallback',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'security.token-or-session-not-validated',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'security.unvalidated-external-input',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'security.unsafe-deserialization',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'security.missing-request-timeout-or-retry',
          appliesTo: 'block',
        }),
      ]),
    );

    const uncheckedKeyFacts = result.data.semantics?.controlFlow?.facts.filter(
      (fact) => fact.kind === 'data-flow.unchecked-map-key-access',
    );

    expect(uncheckedKeyFacts).toHaveLength(1);
  });

  it('suppresses guarded dereferences, keyed writes, and shared-fallback dispatch patterns', () => {
    const result = analyzeTypeScriptFile(
      'src/guarded-runtime.ts',
      [
        "enum CoverType {",
        "  Comprehensive = 'Comprehensive',",
        "  Stationary = 'Stationary',",
        "  ThirdPartyOnly = 'ThirdPartyOnly',",
        '}',
        '',
        'export function guardedReturn(flag: boolean) {',
        "  const user = flag ? { name: 'Ada' } : null;",
        '  if (!user) {',
        "    return 'unknown';",
        '  }',
        '  return user.name;',
        '}',
        '',
        'export function logicalGuard(flag: boolean) {',
        "  const user = flag ? { name: 'Ada' } : null;",
        '  return user && user.name;',
        '}',
        '',
        'export function keyedWrite(values: Record<string, string>, key: string, value: string) {',
        '  values[key] = value;',
        '  return values;',
        '}',
        '',
        'export function logicalHas(valueMap: Map<string, string>, key: string) {',
        '  return valueMap.has(key) && valueMap.get(key);',
        '}',
        '',
        'export function booleanDispatch(flag: boolean) {',
        '  if (flag === true) {',
        '    return 1;',
        '  } else if (flag === false) {',
        '    return 0;',
        '  }',
        '}',
        '',
        'export function switchFallback(status: string) {',
        '  switch (status) {',
        "    case 'open':",
        '      return 1;',
        "    case 'closed':",
        '      return 2;',
        '  }',
        '  return 0;',
        '}',
        '',
        'export function enumSwitch(coverType: CoverType) {',
        '  switch (coverType) {',
        '    case CoverType.Comprehensive:',
        "      return 'comprehensive';",
        '    case CoverType.Stationary:',
        "      return 'stationary';",
        '    case CoverType.ThirdPartyOnly:',
        "      return 'damage to others';",
        '  }',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const facts = result.data.semantics?.controlFlow?.facts ?? [];

    expect(
      facts.filter((fact) => fact.kind === 'data-flow.possible-null-dereference'),
    ).toHaveLength(0);
    expect(
      facts.filter((fact) => fact.kind === 'data-flow.unchecked-map-key-access'),
    ).toHaveLength(0);
    expect(
      facts.filter((fact) => fact.kind === 'control-flow.missing-default-dispatch'),
    ).toHaveLength(0);
  });

  it('emits structural threshold facts for the shipped metric rule set', () => {
    const result = analyzeTypeScriptFile(
      'src/structural.ts',
      [
        'export const serviceUrl = "https://internal.service";',
        '',
        'const fs = {',
        '  promises: {',
        '    readFile: async (_path: string, _encoding: string) => "rows",',
        '  },',
        '};',
        '',
        'const cache = new Set<string>();',
        'let retained: ArrayBuffer;',
        '',
        'declare function useState<T>(value: T): [T, (next: T) => void];',
        '',
        'export function repeated(payload: unknown) {',
        '  const first = JSON.stringify(payload);',
        '  const second = JSON.stringify(payload);',
        '  return first + second;',
        '}',
        '',
        'export function lookup(ids: string[], values: string[]) {',
        '  for (const value of values) {',
        '    if (ids.includes(value)) {',
        '      return value;',
        '    }',
        '  }',
        '}',
        '',
        'export async function readReport() {',
        '  return await fs.promises.readFile("report.csv", "utf8");',
        '}',
        '',
        'export function remember(value: string) {',
        '  cache.add(value);',
        '}',
        '',
        'export async function cacheDownload(response: { arrayBuffer(): Promise<ArrayBuffer> }) {',
        '  retained = await response.arrayBuffer();',
        '  return retained.byteLength;',
        '}',
        '',
        'export function Counter() {',
        '  const [count, setCount] = useState(0);',
        '  setCount(count + 1);',
        '  return count;',
        '}',
        '',
        'export function structural(values: number[][], status: string) {',
        '  let total = 0;',
        '  const one = 1;',
        '  const two = 2;',
        '  const three = 3;',
        '  const four = 4;',
        '  const five = 5;',
        '  const six = 6;',
        '  const seven = 7;',
        '  const eight = 8;',
        '  const nine = 9;',
        '  const ten = 10;',
        '  const eleven = 11;',
        '  const twelve = 12;',
        '  for (const outer of values) {',
        '    for (const inner of outer) {',
        '      if (inner > 7) {',
        '        while (total < inner) {',
        '          if (status === "archived") {',
        '            total += 99;',
        '            break;',
        '          }',
        '          total += inner;',
        '          break;',
        '        }',
        '      }',
        '    }',
        '  }',
        '  if (total > 42) {',
        '    total -= 13;',
        '  }',
        '  return total + one + two + three + four + five + six + seven + eight + nine + ten + eleven + twelve;',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'performance.repeated-expensive-computation',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'performance.inefficient-data-structure-usage',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'performance.large-payload-without-streaming',
          appliesTo: 'block',
        }),
        expect.objectContaining({
          kind: 'performance.unbounded-growth-memory-leak',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'performance.retained-large-object',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'performance.unnecessary-rerenders-from-state-misuse',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'performance.nested-loops-hot-path',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'quality.function-too-large-or-complex',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'quality.deep-nesting',
          appliesTo: 'function',
        }),
        expect.objectContaining({
          kind: 'quality.hardcoded-configuration-values',
          appliesTo: 'file',
        }),
        expect.objectContaining({
          kind: 'quality.magic-numbers-or-strings',
          appliesTo: 'block',
        }),
      ]),
    );
  });
});
