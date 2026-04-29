import { createDiagnostic } from '@critiq/core-diagnostics';

import { createObservedFactFromOffsets } from '../runtime/helpers';

import { analyzePolyglotFile, createRegexPolyglotAdapter } from './analysis';

describe('analyzePolyglotFile', () => {
  it('returns validation diagnostics before collecting facts', () => {
    let collectStateCalled = false;
    const result = analyzePolyglotFile(
      {
        language: 'go',
        detector: 'test-detector',
        validate: () =>
          createDiagnostic({
            code: 'adapter.test.parse-failed',
            message: 'Broken input.',
          }),
        collectState: () => {
          collectStateCalled = true;
          return {};
        },
        collectFacts: () => [],
      },
      'broken.go',
      'broken',
    );

    expect(result.success).toBe(false);
    expect(collectStateCalled).toBe(false);

    if (result.success) {
      throw new Error('Expected analysis failure.');
    }

    expect(result.diagnostics).toEqual([
      expect.objectContaining({
        code: 'adapter.test.parse-failed',
        message: 'Broken input.',
      }),
    ]);
  });

  it('dedupes collected facts and returns a sorted analyzed file', () => {
    const text = ['logger.info(secret)', 'exec(secret)'].join('\n');
    const secretFact = createObservedFactFromOffsets(text, {
      detector: 'test-detector',
      appliesTo: 'function',
      kind: 'security.sensitive-data-in-logs-and-telemetry',
      startOffset: 0,
      endOffset: 19,
      text: 'logger.info(secret)',
    });
    const commandFact = createObservedFactFromOffsets(text, {
      detector: 'test-detector',
      appliesTo: 'block',
      kind: 'security.command-execution-with-request-input',
      startOffset: 20,
      endOffset: text.length,
      text: 'exec(secret)',
    });

    const result = analyzePolyglotFile(
      {
        language: 'ruby',
        detector: 'test-detector',
        collectState: () => ({ secret: true }),
        collectFacts: () => [commandFact, secretFact, secretFact],
      },
      'service.rb',
      text,
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.nodes).toHaveLength(1);
    expect(result.data.semantics?.controlFlow?.facts).toEqual([
      secretFact,
      commandFact,
    ]);
  });
});

describe('createRegexPolyglotAdapter', () => {
  it('builds a source adapter with shared analyze behavior', () => {
    const { analyze, sourceAdapter } = createRegexPolyglotAdapter({
      packageName: '@critiq/adapter-go',
      supportedExtensions: ['.go'] as const,
      supportedLanguages: ['go'] as const,
      definition: {
        language: 'go',
        detector: 'go-detector',
        collectState: () => ({ ok: true }),
        collectFacts: () => [],
      },
    });

    expect(sourceAdapter.packageName).toBe('@critiq/adapter-go');
    expect(sourceAdapter.supportedExtensions).toEqual(['.go']);
    expect(sourceAdapter.supportedLanguages).toEqual(['go']);
    expect(sourceAdapter.analyze).toBe(analyze);
    expect(analyze('service.go', 'package main')).toMatchObject({
      success: true,
      data: expect.objectContaining({
        path: 'service.go',
        language: 'go',
      }),
    });
  });
});
