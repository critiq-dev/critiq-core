import {
  buildAnalyzedFileWithFacts,
  createObservedFactFromOffsets,
  createRangeFromOffsets,
  findCallSnippets,
} from './helpers';

describe('runtime helpers', () => {
  it('creates ranges from offsets across line boundaries', () => {
    const range = createRangeFromOffsets('first line\nsecond line', 6, 16);

    expect(range).toEqual({
      startLine: 1,
      startColumn: 7,
      endLine: 2,
      endColumn: 6,
    });
  });

  it('extracts call snippets with nested delimiters', () => {
    const snippets = findCallSnippets(
      'logger.info(format(secret, lookup(user)))',
      /\blogger\.info\s*\(/g,
    );

    expect(snippets).toEqual([
      expect.objectContaining({
        calleeText: 'logger.info',
        text: 'logger.info(format(secret, lookup(user)))',
        range: expect.objectContaining({
          startLine: 1,
          startColumn: 1,
          endLine: 1,
          endColumn: 42,
        }),
      }),
    ]);
  });

  it('sorts facts when building analyzed files', () => {
    const text = ['later();', 'earlier();'].join('\n');
    const laterFact = createObservedFactFromOffsets(text, {
      detector: 'test-detector',
      appliesTo: 'block',
      kind: 'test.later',
      startOffset: 9,
      endOffset: 18,
      text: 'earlier();',
    });
    const earlierFact = createObservedFactFromOffsets(text, {
      detector: 'test-detector',
      appliesTo: 'block',
      kind: 'test.earlier',
      startOffset: 0,
      endOffset: 8,
      text: 'later();',
    });

    const analyzedFile = buildAnalyzedFileWithFacts(
      'src/example.ts',
      'typescript',
      text,
      [laterFact, earlierFact],
    );

    expect(analyzedFile.semantics?.controlFlow?.facts).toEqual([
      earlierFact,
      laterFact,
    ]);
  });
});
