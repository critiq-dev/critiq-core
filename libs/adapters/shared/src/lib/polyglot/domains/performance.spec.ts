import {
  collectGoPerformanceFacts,
  collectJavaPerformanceFacts,
  collectPhpPerformanceFacts,
  collectRustPerformanceFacts,
  GO_PERFORMANCE_FACT_KINDS,
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

describe('go performance collectors (batch-05 CRT-P)', () => {
  it('flags consecutive append calls on same variable (CRT-P0001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'xs = append(xs, 1)',
        'xs = append(xs, 2)',
        'xs = append(xs, 3)',
        'ys = append(ys, 1)',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.combineAppendCalls,
    );
  });

  it('does not flag single append calls (CRT-P0001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'xs = append(xs, 1, 2, 3)',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.combineAppendCalls),
    ).toBe(false);
  });

  it('flags large array function parameters (CRT-P0003)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'func f(x [1024]int) {}',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.avoidLargeParamCopy,
    );
  });

  it('does not flag small array parameters (CRT-P0003)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'func f(x [64]int) {}',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.avoidLargeParamCopy),
    ).toBe(false);
  });

  it('does not flag pointer or slice parameters (CRT-P0003)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: ['func f(x *[1024]int) {}', 'func g(x []int) {}'].join('\n'),
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.avoidLargeParamCopy),
    ).toBe(false);
  });

  it('flags strings.Index with explicit string() conversion (CRT-P0004)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'strings.Index(string(x), "needle")',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.avoidStringIndexAlloc,
    );
  });

  it('does not flag strings.Index without conversion (CRT-P0004)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'strings.Index(s, "needle")',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.avoidStringIndexAlloc),
    ).toBe(false);
  });

  it('flags range over large fixed-size array (CRT-P0005)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'var xs [2048]byte',
        'for _, x := range xs {',
        '  _ = x',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.avoidLargeRangeCopy,
    );
  });

  it('does not flag range over pointer to array (CRT-P0005)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'var xs [2048]byte',
        'for _, x := range &xs {',
        '  _ = x',
        '}',
      ].join('\n'),
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.avoidLargeRangeCopy),
    ).toBe(false);
  });

  it('flags range over slice of large arrays (CRT-P0006)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'xs := make([][1024]byte, 10)',
        'for _, x := range xs {',
        '  _ = x',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.avoidLargeLoopCopy,
    );
  });

  it('does not flag index-based range over large slice (CRT-P0006)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'xs := make([][1024]byte, 10)',
        'for i := range xs {',
        '  x := &xs[i]',
        '  _ = x',
        '}',
      ].join('\n'),
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.avoidLargeLoopCopy),
    ).toBe(false);
  });
});

describe('go performance collectors (batch-11 GO-P)', () => {
  it('flags function-call || simple-var for reorder (GO-P3001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'if isValid(x) || y {',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.reorderOperands,
    );
  });

  it('does not flag both-side function calls (GO-P3001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'if f(x) || g(y) {',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.reorderOperands),
    ).toBe(false);
  });

  it('does not flag both-side identifiers (GO-P3001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'if x || y {',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.reorderOperands),
    ).toBe(false);
  });

  it('flags three-clause for with zero-assignment body (GO-P4001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'for i := 0; i < len(items); i++ {',
        '  items[i] = 0',
        '}',
      ].join('\n'),
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.nonIdiomaticSliceZeroing,
    );
  });

  it('does not flag idiomatic range-based zeroing (GO-P4001)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: [
        'for i := range items {',
        '  items[i] = 0',
        '}',
      ].join('\n'),
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.nonIdiomaticSliceZeroing),
    ).toBe(false);
  });

  it('flags []rune(str)[0] pattern (GO-P4006)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'r := []rune(s)[0]',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.utf8DecodeRune,
    );
  });

  it('does not flag utf8.DecodeRuneInString usage (GO-P4006)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'r, size := utf8.DecodeRuneInString(s)',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.utf8DecodeRune),
    ).toBe(false);
  });

  it('flags .Write([]byte(fmt.Sprintf(...))) pattern (GO-P4007)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'w.Write([]byte(fmt.Sprintf("A: %d", a)))',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.fmtFprint,
    );
  });

  it('flags .Write(fmt.Sprint(...)) pattern (GO-P4007)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'w.Write(fmt.Sprint(x))',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.fmtFprint,
    );
  });

  it('does not flag bare fmt.Sprintf without Write (GO-P4007)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'result := fmt.Sprintf("hello %s", name)',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.fmtFprint),
    ).toBe(false);
  });

  it('flags .Write([]byte(...)) pattern (GO-P4008)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'w.Write([]byte("hello world"))',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.writerWriteString,
    );
  });

  it('flags io.WriteString(...) pattern (GO-P4008)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'io.WriteString(w, "hello")',
    });

    expect(facts.map((f) => f.kind)).toContain(
      GO_PERFORMANCE_FACT_KINDS.writerWriteString,
    );
  });

  it('does not flag bare .Write() without []byte (GO-P4008)', () => {
    const facts = collectGoPerformanceFacts({
      path: 'service.go',
      detector: 'go-detector',
      text: 'w.Write(data)',
    });

    expect(
      facts.some((f) => f.kind === GO_PERFORMANCE_FACT_KINDS.writerWriteString),
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
