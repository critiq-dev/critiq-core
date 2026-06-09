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

  describe('go-batch-03 CRT-D correctness', () => {
    it('flags unreachable switch case after return without fallthrough', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) {',
          '  switch x {',
          '  case 1:',
          '    return',
          '  case 2:',
          '    println("never")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unreachableSwitchCase,
      );
    });

    it('does not flag case with fallthrough', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) {',
          '  switch x {',
          '  case 1:',
          '    println("one")',
          '    fallthrough',
          '  case 2:',
          '    println("two")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.unreachableSwitchCase,
        ),
      ).toHaveLength(0);
    });

    it('flags duplicate function arguments foo(x, x)', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func main() {',
          '  x := 1',
          '  _ = fmt.Sprintf("%d %d", x, x)',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.duplicateFunctionArguments,
      );
    });

    it('does not flag different function arguments foo(x, y)', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func main() {',
          '  x, y := 1, 2',
          '  _ = fmt.Sprintf("%d %d", x, y)',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.duplicateFunctionArguments,
        ),
      ).toHaveLength(0);
    });

    it('flags duplicate branch bodies', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x, y, z bool) int {',
          '  if x { return 1 } else if y { return 1 } else { return 1 }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.duplicateBranchBody,
      );
    });

    it('does not flag different branch bodies', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x bool) int {',
          '  if x {',
          '    return 1',
          '  } else {',
          '    return 2',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.duplicateBranchBody,
        ),
      ).toHaveLength(0);
    });

    it('flags duplicate switch cases', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) {',
          '  switch x {',
          '  case 1:',
          '    println("one")',
          '  case 1:',
          '    println("dup")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.duplicateSwitchCases,
      );
    });

    it('does not flag distinct switch cases', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) {',
          '  switch x {',
          '  case 1:',
          '    println("one")',
          '  case 2:',
          '    println("two")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.duplicateSwitchCases,
        ),
      ).toHaveLength(0);
    });

    it('flags identical binary operands x == x', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) bool {',
          '  return x == x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.identicalBinaryOperands,
      );
    });

    it('does not flag different binary operands x == y', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x, y int) bool {',
          '  return x == y',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.identicalBinaryOperands,
        ),
      ).toHaveLength(0);
    });

    it('flags flag pointer immediate deref', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "flag"',
          '',
          'func main() {',
          '  name := *flag.String("name", "", "")',
          '  _ = name',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.flagPointerImmediateDeref,
      );
    });

    it('does not flag regular flag.String call without deref', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "flag"',
          '',
          'func main() {',
          '  name := flag.String("name", "", "")',
          '  _ = name',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.flagPointerImmediateDeref,
        ),
      ).toHaveLength(0);
    });

    it('flags terminal call with defer (os.Exit)', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "os"',
          '',
          'func run() {',
          '  defer println("cleanup")',
          '  os.Exit(1)',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.terminalCallWithDefer,
      );
    });

    it('does not flag defer without terminal call', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "os"',
          '',
          'func run() {',
          '  defer println("cleanup")',
          '  return',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.terminalCallWithDefer,
        ),
      ).toHaveLength(0);
    });

    it('flags nil error returned', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() (any, error) {',
          '  return nil, nil',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.nilErrorReturned,
      );
    });

    it('does not flag return val, nil', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() (string, error) {',
          '  return "ok", nil',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.nilErrorReturned,
        ),
      ).toHaveLength(0);
    });
  });

  describe('go-batch-04 CRT-D correctness', () => {
    it('flags off-by-one index arr[len(arr)]', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  arr := []int{1, 2, 3}',
          '  _ = arr[len(arr)]',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.offByOneIndex,
      );
    });

    it('does not flag safe index arr[len(arr)-1]', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  arr := []int{1, 2, 3}',
          '  _ = arr[len(arr)-1]',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.offByOneIndex,
        ),
      ).toHaveLength(0);
    });

    it('flags incomplete nil check xs != nil && xs[0]', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var xs []int',
          '  if xs != nil && xs[0] == 1 {',
          '    println("found")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.incompleteNilCheck,
      );
    });

    it('does not flag len check xs != nil && len(xs) > 0', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var xs []int',
          '  if xs != nil && len(xs) > 0 {',
          '    println("ok")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.incompleteNilCheck,
        ),
      ).toHaveLength(0);
    });

    it('flags boolean simplification x > y - 1', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x, y int) bool {',
          '  return x > y - 1',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.booleanSimplification,
      );
    });

    it('flags boolean simplification x < y || x == y', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x, y int) bool {',
          '  return x < y || x == y',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.booleanSimplification,
      );
    });

    it('does not flag already simplified x >= y', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x, y int) bool {',
          '  return x >= y',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.booleanSimplification,
        ),
      ).toHaveLength(0);
    });

    it('flags suspicious regex pattern with unescaped dot', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "regexp"',
          '',
          'func fn() {',
          '  re := regexp.MustCompile("google.com")',
          '  _ = re',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.suspiciousRegexPattern,
      );
    });

    it('does not flag regex with escaped dot', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "regexp"',
          '',
          'func fn() {',
          '  re := regexp.MustCompile("google\\\\.com")',
          '  _ = re',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.suspiciousRegexPattern,
        ),
      ).toHaveLength(0);
    });

    it('flags integer truncation int16(x) < y', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var a int32 = 100',
          '  var b int16 = 50',
          '  _ = int16(a) < b',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.integerTruncation,
      );
    });

    it('does not flag safe comparison without truncation', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var a int32 = 100',
          '  var b int32 = 50',
          '  _ = a < b',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.integerTruncation,
        ),
      ).toHaveLength(0);
    });
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

  describe('go-batch-06 CRT-S unnecessary dereference', () => {
    it('flags unnecessary dereference for field access (*ptr).field', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type S struct { Name string }',
          '',
          'func fn(s *S) string {',
          '  return (*s).Name',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
      );
    });

    it('flags unnecessary double dereference (**ptr).field', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type S struct { Name string }',
          '',
          'func fn(s **S) string {',
          '  return (**s).Name',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
      );
    });

    it('flags unnecessary dereference for index access (*arr)[0]', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(arr *[3]int) int {',
          '  return (*arr)[0]',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
      );
    });

    it('does not flag direct field access without dereference', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type S struct { Name string }',
          '',
          'func fn(s *S) string {',
          '  return s.Name',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
        ),
      ).toHaveLength(0);
    });

    it('does not flag simple dereference without field or index access', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(ptr *int) int {',
          '  return *ptr',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
        ),
      ).toHaveLength(0);
    });

    it('does not flag dereference inside string literals', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() string {',
          '  return "(*s).field"',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
        ),
      ).toHaveLength(0);
    });

    it('does not flag dereference inside backtick literals', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() string {',
          '  return `(*s).field`',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.unnecessaryDereference,
        ),
      ).toHaveLength(0);
    });
  });

  describe('go-batch-07 GO-C correctness — deferred func literal / redundant type declaration', () => {
    it('flags deferred func literal with single expression-statement body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func cleanup() {}',
          '',
          'func run() {',
          '  defer func() { cleanup() }()',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
      );
    });

    it('flags deferred func literal with method call body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type DB struct{}',
          '',
          'func (db *DB) Close() {}',
          '',
          'func run(db *DB) {',
          '  defer func() { db.Close() }()',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
      );
    });

    it('does not flag deferred func literal with multi-statement body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func run() {',
          '  defer func() {',
          '    cleanup()',
          '    log()',
          '  }()',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
        ),
      ).toHaveLength(0);
    });

    it('does not flag deferred func literal with control flow', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func run() {',
          '  defer func() {',
          '    if err != nil {',
          '      log()',
          '    }',
          '  }()',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
        ),
      ).toHaveLength(0);
    });

    it('does not flag deferred func literal with parameters', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func run() {',
          '  defer func(msg string) { fmt.Println(msg) }("hello")',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
        ),
      ).toHaveLength(0);
    });

    it('does not flag empty deferred func literal body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func run() {',
          '  defer func() {}()',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.deferredFuncLiteral,
        ),
      ).toHaveLength(0);
    });

    it('flags redundant type int in var declaration', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var count int = 10',
          '  _ = count',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
      );
    });

    it('flags redundant type string in var declaration', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var label string = "hello"',
          '  _ = label',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
      );
    });

    it('flags redundant type bool in var declaration', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var done bool = true',
          '  var active bool = false',
          '  _, _ = done, active',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
        ),
      ).toHaveLength(2);
    });

    it('flags redundant type float64 in var declaration', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var rate float64 = 3.14',
          '  _ = rate',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
      );
    });

    it('does not flag var with nil RHS', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  var s *string = nil',
          '  _ = s',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
        ),
      ).toHaveLength(0);
    });

    it('does not flag var with function call RHS', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() string { return "x" }',
          '',
          'func run() {',
          '  var name string = fn()',
          '  _ = name',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
        ),
      ).toHaveLength(0);
    });

    it('does not flag short variable declaration', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() {',
          '  count := 10',
          '  _ = count',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.redundantTypeDeclaration,
        ),
      ).toHaveLength(0);
    });
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

  describe('go-batch-12 (GO-R) correctness', () => {
    it('GO-R3001: flags interface{} in type positions', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(m map[string]interface{}) {',
          '  var x interface{}',
          '  _ = x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.interfaceAnyPreferred,
      );
    });

    it('GO-R3001: does not flag code already using any', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(m map[string]any) {',
          '  var x any',
          '  _ = x',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.interfaceAnyPreferred,
        ),
      ).toHaveLength(0);
    });

    it('GO-R3002: flags if-else with return in if-body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) int {',
          '  if x > 0 {',
          '    return x',
          '  } else {',
          '    return 0',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unnecessaryElseReturn,
      );
    });

    it('GO-R3002: does not flag if without else', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(x int) {',
          '  if x > 0 {',
          '    return',
          '  }',
          '  println("done")',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.unnecessaryElseReturn,
        ),
      ).toHaveLength(0);
    });

    it('GO-R3003: flags bare return in named-return function', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() (result int) {',
          '  if true {',
          '    return',
          '  }',
          '  result = 42',
          '  return',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.bareReturn,
      );
    });

    it('GO-R3003: does not flag bare return in single-statement function', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn() (result int) {',
          '  return',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.bareReturn,
        ),
      ).toHaveLength(0);
    });

    it('GO-R3004: flags boolean literal in expression', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(flag bool) bool {',
          '  return flag == true',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.booleanLiteralInExpression,
      );
    });

    it('GO-R3004: does not flag plain boolean usage', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func fn(flag bool) bool {',
          '  return flag',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.booleanLiteralInExpression,
        ),
      ).toHaveLength(0);
    });

    it('GO-R3005: flags unexported struct with capitalized fields', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type config struct {',
          '  Name string',
          '  Value int',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.unexportedCapitalName,
      );
    });

    it('GO-R3005: does not flag exported struct with capitalized fields', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type Config struct {',
          '  Name string',
          '  Value int',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.unexportedCapitalName,
        ),
      ).toHaveLength(0);
    });

    it('GO-R4001: flags http.NewRequest with nil body', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "net/http"',
          '',
          'func main() {',
          '  req, _ := http.NewRequest("GET", "https://example.com", nil)',
          '  _ = req',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.httpNobodyNil,
      );
    });

    it('GO-R4001: does not flag http.NewRequest with http.NoBody', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "net/http"',
          '',
          'func main() {',
          '  req, _ := http.NewRequest("GET", "https://example.com", http.NoBody)',
          '  _ = req',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_CORRECTNESS_FACT_KINDS.httpNobodyNil,
        ),
      ).toHaveLength(0);
    });

    it('GO-R4003: flags strings.Join with empty separator', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "strings"',
          '',
          'func fn(parts []string) string {',
          '  return strings.Join(parts, "")',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_CORRECTNESS_FACT_KINDS.stringConcatSimplify,
      );
    });

    it('GO-R4003: does not flag strings.Join with non-empty separator', () => {
      const facts = collectGoCorrectnessFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "strings"',
          '',
          'func fn(parts []string) string {',
          '  return strings.Join(parts, ", ")',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_CORRECTNESS_FACT_KINDS.stringConcatSimplify,
        ),
      ).toHaveLength(0);
    });
  });

  describe('batch 14 (GO-W correctness heuristics)', () => {
    describe('GO-W1001 — impossible interface nil check', () => {
      it('flags error variable compared to nil', () => {
        const facts = collectGoCorrectnessFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'type MyError struct{}',
            'func (e *MyError) Error() string { return "err" }',
            '',
            'func maybeFail() *MyError { return nil }',
            '',
            'func check() {',
            '  var err error = maybeFail()',
            '  if err != nil {',
            '    println("never nil")',
            '  }',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_CORRECTNESS_FACT_KINDS.impossibleInterfaceNilCheck,
        );
      });

      it('does not flag direct concrete type comparison', () => {
        const facts = collectGoCorrectnessFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'type MyError struct{}',
            'func (e *MyError) Error() string { return "err" }',
            '',
            'func maybeFail() *MyError { return nil }',
            '',
            'func check() {',
            '  err := maybeFail()',
            '  if err != nil {',
            '    println("ok")',
            '  }',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) =>
              f.kind ===
              GO_CORRECTNESS_FACT_KINDS.impossibleInterfaceNilCheck,
          ),
        ).toHaveLength(0);
      });
    });

    describe('GO-W1002 — duplicate if/else condition', () => {
      it('flags if x { ... } else if x { ... }', () => {
        const facts = collectGoCorrectnessFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func check(x int) {',
            '  if x > 5 {',
            '    println("gt")',
            '  } else if x > 5 {',
            '    println("still gt")',
            '  }',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_CORRECTNESS_FACT_KINDS.duplicateIfElseCondition,
        );
      });

      it('does not flag different conditions', () => {
        const facts = collectGoCorrectnessFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func check(x, y int) {',
            '  if x > 5 {',
            '    println("gt")',
            '  } else if y > 5 {',
            '    println("still gt")',
            '  }',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) =>
              f.kind ===
              GO_CORRECTNESS_FACT_KINDS.duplicateIfElseCondition,
          ),
        ).toHaveLength(0);
      });
    });
  });
});
