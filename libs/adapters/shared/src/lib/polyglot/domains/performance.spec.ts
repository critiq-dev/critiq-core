import {
  collectJavaPerformanceFacts,
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

describe('java performance collectors', () => {
  it('flags Thread passed where Runnable expected', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'Service.java',
      detector: 'java-detector',
      text: [
        'class Service {',
        '  void runTasks(ExecutorService exec, Runnable task) {',
        '    exec.submit(new Thread(task));',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      'java.performance.thread-as-runnable',
    );
  });

  it('flags Maps and Sets of URL', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'Cache.java',
      detector: 'java-detector',
      text: [
        'import java.net.URL;',
        'import java.util.HashMap;',
        'import java.util.Map;',
        'class Cache {',
        '  Map<URL, String> urlCache = new HashMap<>();',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      'java.performance.url-in-collection',
    );
  });

  it('flags new String("literal")', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  String getGreeting() {',
        '    return new String("hello");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      'java.performance.inefficient-string-constructor',
    );
  });

  it('flags new String() no-arg', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  String getEmpty() {',
        '    return new String();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      'java.performance.empty-string-constructor',
    );
  });

  it('does not flag new String(char[]) as empty constructor', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  String fromChars(char[] chars) {',
        '    return new String(chars);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.empty-string-constructor'),
    ).toHaveLength(0);
  });

  it('does not flag normal string literal assignment', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  String getGreeting() {',
        '    return "hello";',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) =>
          f.kind === 'java.performance.inefficient-string-constructor' ||
          f.kind === 'java.performance.empty-string-constructor',
      ),
    ).toHaveLength(0);
  });

  it('does not flag normal thread usage', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'Service.java',
      detector: 'java-detector',
      text: [
        'class Service {',
        '  void runTasks(ExecutorService exec, Runnable task) {',
        '    exec.submit(task);',
        '    new Thread(task).start();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.thread-as-runnable'),
    ).toHaveLength(0);
  });

  it('flags toString() on string literal', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  String getValue() {',
        '    return "hello".toString();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      'java.performance.string-to-string',
    );
  });

  it('flags explicit System.gc()', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  void cleanup() {',
        '    System.gc();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      'java.performance.explicit-gc',
    );
  });

  it('flags explicit Runtime.getRuntime().gc()', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  void cleanup() {',
        '    Runtime.getRuntime().gc();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      'java.performance.explicit-gc',
    );
  });

  it('flags new Boolean() constructor', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Boolean getFlag() {',
        '    return new Boolean(true);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      'java.performance.boxed-boolean-constructor',
    );
  });

  it('does not flag Boolean.valueOf()', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Boolean getFlag() {',
        '    return Boolean.valueOf(true);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.boxed-boolean-constructor'),
    ).toHaveLength(0);
  });

  it('flags new Integer() and new Long() constructors', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Integer getInt() {',
        '    return new Integer(42);',
        '  }',
        '  Long getLong() {',
        '    return new Long(42L);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.boxed-integer-constructor'),
    ).toHaveLength(2);
  });

  it('does not flag Integer.valueOf()', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Integer getInt() {',
        '    return Integer.valueOf(42);',
        '  }',
        '  Long getLong() {',
        '    return Long.valueOf(42L);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.boxed-integer-constructor'),
    ).toHaveLength(0);
  });

  it('flags new Float() and new Double() constructors', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Float getFloat() {',
        '    return new Float(3.14f);',
        '  }',
        '  Double getDouble() {',
        '    return new Double(3.14);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.boxed-double-constructor'),
    ).toHaveLength(2);
  });

  it('does not flag Float.valueOf()', () => {
    const facts = collectJavaPerformanceFacts({
      path: 'App.java',
      detector: 'java-detector',
      text: [
        'class App {',
        '  Float getFloat() {',
        '    return Float.valueOf(3.14f);',
        '  }',
        '  Double getDouble() {',
        '    return Double.valueOf(3.14);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === 'java.performance.boxed-double-constructor'),
    ).toHaveLength(0);
  });
});
