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

  it('emits control-flow facts for implicit returns, unreachable code, and catch handling', () => {
    const result = analyzeTypeScriptFile(
      'src/control-flow.ts',
      [
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
});
