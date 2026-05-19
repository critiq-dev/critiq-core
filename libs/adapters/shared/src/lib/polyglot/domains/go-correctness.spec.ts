import {
  collectGoCorrectnessFacts,
  GO_CORRECTNESS_FACT_KINDS,
} from './go-correctness';

describe('go-correctness collectors', () => {
  it('flags nil map assignment when declared with var', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'func main() {',
        '  var counts map[string]int',
        '  counts["a"] = 1',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.nilMapAssignment,
    );
  });

  it('does not flag map writes when the map was initialized with make', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'func main() {',
        '  var counts map[string]int',
        '  counts = make(map[string]int)',
        '  counts["a"] = 1',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_CORRECTNESS_FACT_KINDS.nilMapAssignment,
      ),
    ).toHaveLength(0);
  });

  it('flags defer Close before err check', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func read(path string) error {',
        '  file, err := os.Open(path)',
        '  defer file.Close()',
        '  if err != nil {',
        '    return err',
        '  }',
        '  _ = file',
        '  return nil',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.deferCloseBeforeCheck,
    );
  });

  it('does not flag defer Close after err check', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func read(path string) error {',
        '  file, err := os.Open(path)',
        '  if err != nil {',
        '    return err',
        '  }',
        '  defer file.Close()',
        '  _ = file',
        '  return nil',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_CORRECTNESS_FACT_KINDS.deferCloseBeforeCheck,
      ),
    ).toHaveLength(0);
  });

  it('flags nil context passed to Context-accepting calls', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "net/http"',
        '',
        'func main() {',
        '  _, _ = http.NewRequestWithContext(nil, "GET", "https://example.com", nil)',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.nilContextPassed,
    );
  });

  it('does not flag context.TODO() passed to Context-accepting calls', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import (',
        '  "context"',
        '  "net/http"',
        ')',
        '',
        'func main() {',
        '  _, _ = http.NewRequestWithContext(context.TODO(), "GET", "https://example.com", nil)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_CORRECTNESS_FACT_KINDS.nilContextPassed,
      ),
    ).toHaveLength(0);
  });

  it('flags time.Tick usage', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "time"',
        '',
        'func main() {',
        '  ch := time.Tick(time.Second)',
        '  _ = ch',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.timeTickLeak,
    );
  });

  it('flags wg.Add inside go func', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "sync"',
        '',
        'func main() {',
        '  var wg sync.WaitGroup',
        '  go func() {',
        '    wg.Add(1)',
        '    defer wg.Done()',
        '  }()',
        '  wg.Wait()',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.waitgroupAddInGoroutine,
    );
  });

  it('does not flag wg.Add before go func', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "sync"',
        '',
        'func main() {',
        '  var wg sync.WaitGroup',
        '  wg.Add(1)',
        '  go func() {',
        '    defer wg.Done()',
        '  }()',
        '  wg.Wait()',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_CORRECTNESS_FACT_KINDS.waitgroupAddInGoroutine,
      ),
    ).toHaveLength(0);
  });

  it('flags standalone append result', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'func main() {',
        '  items := []string{}',
        '  append(items, "x")',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.unusedAppendResult,
    );
  });

  it('does not flag assigned append result', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'func main() {',
        '  items := []string{}',
        '  items = append(items, "x")',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_CORRECTNESS_FACT_KINDS.unusedAppendResult,
      ),
    ).toHaveLength(0);
  });

  it('flags defer inside for range loop', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func main(paths []string) {',
        '  for _, p := range paths {',
        '    f, _ := os.Open(p)',
        '    defer f.Close()',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      GO_CORRECTNESS_FACT_KINDS.deferInLoop,
    );
  });

  it('does not flag defer inside a closure invoked in a loop', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func main(paths []string) {',
        '  for _, p := range paths {',
        '    func(path string) {',
        '      f, _ := os.Open(path)',
        '      defer f.Close()',
        '      _ = f',
        '    }(p)',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_CORRECTNESS_FACT_KINDS.deferInLoop,
      ),
    ).toHaveLength(0);
  });

  it('does not flag safe Go patterns', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      text: [
        'package main',
        '',
        'import (',
        '  "context"',
        '  "net/http"',
        '  "sync"',
        '  "time"',
        ')',
        '',
        'func main() {',
        '  m := map[string]int{}',
        '  m["a"] = 1',
        '  _ = m',
        '  ticker := time.NewTicker(time.Second)',
        '  defer ticker.Stop()',
        '  var wg sync.WaitGroup',
        '  wg.Add(1)',
        '  go func() {',
        '    defer wg.Done()',
        '    _, _ = http.NewRequestWithContext(context.Background(), "GET", "https://example.com", nil)',
        '  }()',
        '  wg.Wait()',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('returns no facts for paths suppressed via _test.go', () => {
    const facts = collectGoCorrectnessFacts({
      detector: 'go-detector',
      path: 'service_test.go',
      text: [
        'package main',
        '',
        'func TestSomething(t *testing.T) {',
        '  var m map[string]int',
        '  m["x"] = 1',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
