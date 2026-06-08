import {
  collectPhpPerformanceFacts,
  collectRustPerformanceFacts,
  PHP_PERFORMANCE_FACT_KINDS,
  RUST_PERFORMANCE_FACT_KINDS,
} from './performance';

describe('php performance collectors', () => {
  it('flags preg calls inside loops', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'service.php',
      detector: 'php-detector',
      text: [
        'for ($i = 0; $i < count($items); $i++) {',
        '  preg_match("/\\d+/", $items[$i]);',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_PERFORMANCE_FACT_KINDS.noRegexConstructionInLoop,
    );
  });

  it('flags sync filesystem calls in request-handling code', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'handler.php',
      detector: 'php-detector',
      text: [
        'function handleRequest(): void {',
        '  $path = $_GET["path"];',
        '  $contents = file_get_contents($path);',
        '}',
      ].join('\n'),
      state: {
        taintedIdentifiers: new Set(['path']),
        sqlInterpolatedIdentifiers: new Set(),
      },
      matchesTainted: (expression, scanState) =>
        /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/u.test(expression) ||
        [...scanState.taintedIdentifiers].some((identifier) =>
          new RegExp(`\\$${identifier}\\b`, 'u').test(expression),
        ),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_PERFORMANCE_FACT_KINDS.noSyncFsInRequestPath,
    );
  });

  it('does not flag sync filesystem calls in top-level security fixtures', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'app.php',
      detector: 'php-detector',
      text: [
        '$reportName = $_GET["report"];',
        'readfile($reportName);',
        'file_get_contents("http://api.example.com/users");',
      ].join('\n'),
      state: {
        taintedIdentifiers: new Set(['reportName']),
        sqlInterpolatedIdentifiers: new Set(),
      },
      matchesTainted: (expression, scanState) =>
        /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/u.test(expression) ||
        [...scanState.taintedIdentifiers].some((identifier) =>
          new RegExp(`\\$${identifier}\\b`, 'u').test(expression),
        ),
    });

    expect(facts.map((fact) => fact.kind)).not.toContain(
      PHP_PERFORMANCE_FACT_KINDS.noSyncFsInRequestPath,
    );
  });

  it('flags expensive calls in loop conditions', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'service.php',
      detector: 'php-detector',
      text: 'while ($index < count($items)) { $index++; }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_PERFORMANCE_FACT_KINDS.expensiveLoopCondition,
    );
  });

  it('flags unbounded promise concurrency in PHP', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'service.php',
      detector: 'php-detector',
      text: 'GuzzleHttp\\Promise\\all($items);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_PERFORMANCE_FACT_KINDS.noUnboundedConcurrency,
    );
  });

  it('does not emit unbounded concurrency facts for Promise.all in PHP', () => {
    const facts = collectPhpPerformanceFacts({
      path: 'service.php',
      detector: 'php-detector',
      text: 'Promise.all($items->map(fn($item) => task($item)));',
    });

    expect(
      facts.some((fact) => fact.kind.includes('no-unbounded-concurrency')),
    ).toBe(false);
  });
});

describe('rust performance collectors', () => {
  it('flags single-char string literal in find', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.find("o");',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    );
  });

  it('flags single-char string literal in split', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.split("x");',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    );
  });

  it('flags single-char string literal in contains', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.contains("a");',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    );
  });

  it('flags single-char string literal in starts_with', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.starts_with("H");',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    );
  });

  it('flags single-char string literal in replace first arg', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.replace("e", "E");',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern,
    );
  });

  it('does not flag char literals', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: "s.find('o');",
    });

    expect(
      facts.some((fact) =>
        fact.kind.includes(RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern),
      ),
    ).toBe(false);
  });

  it('does not flag multi-character strings', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.split("hello");',
    });

    expect(
      facts.some((fact) =>
        fact.kind.includes(RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern),
      ),
    ).toBe(false);
  });

  it('does not flag empty strings', () => {
    const facts = collectRustPerformanceFacts({
      path: 'test.rs',
      detector: 'rust-detector',
      text: 's.split("");',
    });

    expect(
      facts.some((fact) =>
        fact.kind.includes(RUST_PERFORMANCE_FACT_KINDS.singleCharStringLiteralPattern),
      ),
    ).toBe(false);
  });
});
