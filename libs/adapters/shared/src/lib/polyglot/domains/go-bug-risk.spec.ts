import {
  collectGoBugRiskFacts,
  GO_BUG_RISK_FACT_KINDS,
} from './go-bug-risk';

describe('go-bug-risk collectors', () => {
  describe('GO-E1000 — gin.LoadHTMLGlob ill-formed', () => {
    it('flags gin.LoadHTMLGlob call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "github.com/gin-gonic/gin"',
          '',
          'func setup() {',
          '  r := gin.Default()',
          '  r.LoadHTMLGlob("templates/*.htm[l")',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.ginLoadHTMLGlobIllFormed,
      );
    });

    it('does not flag files without LoadHTMLGlob', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func setup() {',
          '  println("hello")',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.ginLoadHTMLGlobIllFormed,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1001 — Redis arg count', () => {
    it('flags MemoryUsage call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "github.com/redis/go-redis/v9"',
          '',
          'func check(client *redis.Client) {',
          '  client.MemoryUsage("key", "extra")',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.redisIncorrectArgCount,
      );
    });

    it('does not flag without redis variadic calls', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: 'package main\nfunc main() { println("ok") }\n',
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.redisIncorrectArgCount,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1002 — Redis unimplemented methods', () => {
    it('flags Sync(ctx) call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "context"',
          '',
          'type Client struct{}',
          '',
          'func (c *Client) Sync(ctx context.Context) {}',
          '',
          'func run() {',
          '  var c Client',
          '  c.Sync(context.Background())',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.redisUnimplementedMethod,
      );
    });

    it('does not flag without Sync/Quit', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: 'package main\nfunc main() { println("ok") }\n',
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.redisUnimplementedMethod,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1003 — etcd Compare operator', () => {
    it('flags clientv3.Compare call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import clientv3 "go.etcd.io/etcd/client/v3"',
          '',
          'func txn() {',
          '  clientv3.Compare(clientv3.Value("key"), "=", "val")',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.etcdInvalidCompareOperator,
      );
    });

    it('does not flag without Compare', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: 'package main\nfunc main() { println("ok") }\n',
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.etcdInvalidCompareOperator,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1004 — GORM Where zero values', () => {
    it('flags Where(&Struct{}) call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type User struct{ Name string }',
          'type DB struct{}',
          'func (DB) Where(q interface{}) {}',
          '',
          'func run() {',
          '  var db DB',
          '  db.Where(&User{Name: "Alice"})',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.gormWhereZeroValues,
      );
    });

    it('does not flag without Where', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: 'package main\nfunc main() { println("ok") }\n',
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.gormWhereZeroValues,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1005 — GORM Updates zero values', () => {
    it('flags Updates(Struct{}) call', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'type User struct{ Name string }',
          'type DB struct{}',
          'func (DB) Model(v interface{}) *DB { return &DB{} }',
          'func (DB) Updates(v interface{}) {}',
          '',
          'func run() {',
          '  var db DB',
          '  var u User',
          '  db.Model(&u).Updates(User{Name: ""})',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.gormUpdatesZeroValues,
      );
    });

    it('does not flag without Updates', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: 'package main\nfunc main() { println("ok") }\n',
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.gormUpdatesZeroValues,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1006 — Signedness casting', () => {
    it('flags narrowing cast', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func convert() {',
          '  var val int',
          '  result := int8(val)',
          '  _ = result',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.signednessCasting,
      );
    });

    it('does not flag widening cast', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func convert() {',
          '  var val int32',
          '  result := int64(val)',
          '  _ = result',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.signednessCasting,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1007 — Hidden goroutine', () => {
    it('flags function body wrapped in go func', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "fmt"',
          '',
          'func doWork() {',
          '  go func() {',
          '    fmt.Println("working")',
          '  }()',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.hiddenGoroutine,
      );
    });

    it('does not flag normal function', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "fmt"',
          '',
          'func doWork() {',
          '  fmt.Println("working")',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.hiddenGoroutine,
        ),
      ).toHaveLength(0);
    });

    it('does not flag function with go func plus other code', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'import "fmt"',
          '',
          'func doWork() {',
          '  fmt.Println("preparing")',
          '  go func() {',
          '    fmt.Println("working")',
          '  }()',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) => f.kind === GO_BUG_RISK_FACT_KINDS.hiddenGoroutine,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1008 — Poorly formed nilness guards', () => {
    it('flags x == nil && x.Method()', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badGuard(cmd *Cmd) int {',
          '  if cmd == nil && cmd.Execute() == 0 {',
          '    return 0',
          '  }',
          '  return 1',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
      );
    });

    it('flags x != nil || x.Method()', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badGuard(cmd *Cmd) int {',
          '  if cmd != nil || cmd.Execute() == 0 {',
          '    return 0',
          '  }',
          '  return 1',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
      );
    });

    it('flags ptr == nil && ptr.field', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badGuard(p *Config) {',
          '  if p == nil && p.field {',
          '    println("bad")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
      );
    });

    it('flags qualified identifier a.b == nil && a.b.method()', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badGuard() {',
          '  if a.b == nil && a.b.method() {',
          '    println("bad")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
      );
    });

    it('does not flag correct AND guard x != nil && x.Method()', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func goodGuard(cmd *Cmd) int {',
          '  if cmd != nil && cmd.Execute() == 0 {',
          '    return 0',
          '  }',
          '  return 1',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
        ),
      ).toHaveLength(0);
    });

    it('does not flag correct OR guard x == nil || x.Method()', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func goodGuard(cmd *Cmd) int {',
          '  if cmd == nil || cmd.Execute() == 0 {',
          '    return 0',
          '  }',
          '  return 1',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
        ),
      ).toHaveLength(0);
    });

    it('does not flag different identifiers', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func unrelated() {',
          '  if x == nil && y.method() {',
          '    println("ok")',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
        ),
      ).toHaveLength(0);
    });

    it('does not flag separate statements', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func safe() {',
          '  if x == nil { return }',
          '  x.method()',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.poorlyFormedNilnessGuards,
        ),
      ).toHaveLength(0);
    });
  });

  describe('GO-E1009 — Compound assignment misuse', () => {
    it('flags x += x + y', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badCompound(x, y int) int {',
          '  x += x + y',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
      );
    });

    it('flags x += x - y', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badCompound(x, y int) int {',
          '  x += x - y',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
      );
    });

    it('flags x -= x + y', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badCompound(x, y int) int {',
          '  x -= x + y',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
      );
    });

    it('flags x -= x - y', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func badCompound(x, y int) int {',
          '  x -= x - y',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
      );
    });

    it('flags with different identifier: total += total + delta', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func calc(total, delta int) int {',
          '  total += total + delta',
          '  return total',
          '}',
        ].join('\n'),
      });

      expect(facts.map((f) => f.kind)).toContain(
        GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
      );
    });

    it('does not flag simple compound x += y', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func ok(x, y int) int {',
          '  x += y',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
        ),
      ).toHaveLength(0);
    });

    it('does not flag a += b + c (different identifiers)', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func ok(m, n, p int) int {',
          '  m += n + p',
          '  return m',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
        ),
      ).toHaveLength(0);
    });

    it('does not flag x += 1 (constant, not identifier)', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        text: [
          'package main',
          '',
          'func ok(x int) int {',
          '  x += 1',
          '  return x',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (f) =>
            f.kind === GO_BUG_RISK_FACT_KINDS.compoundAssignmentMisuse,
        ),
      ).toHaveLength(0);
    });
  });

  describe('batch 14 (GO-W bug risk heuristics)', () => {
    describe('GO-W1000 — deprecated Redis methods', () => {
      it('flags client.XTrim call', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "github.com/redis/go-redis/v9"',
            'import "context"',
            '',
            'func check(client *redis.Client) {',
            '  client.XTrim(context.Background(), "key", 0)',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.redisDeprecatedMethod,
        );
      });

      it('flags .XTrimApprox call', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func check() {',
            '  rdb.XTrimApprox(ctx, "key", 1000)',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.redisDeprecatedMethod,
        );
      });

      it('does not flag .XAdd (valid method)', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func check() {',
            '  client.XAdd(ctx, "key")',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) => f.kind === GO_BUG_RISK_FACT_KINDS.redisDeprecatedMethod,
          ),
        ).toHaveLength(0);
      });
    });

    describe('GO-W1003 — etcd GetLogger misuse', () => {
      it('flags GetLogger call with etcd import', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "go.etcd.io/etcd/client/v3"',
            '',
            'func check() {',
            '  log := client.GetLogger()',
            '  _ = log',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.etcdGetLoggerMisuse,
        );
      });

      it('does not flag GetLogger without etcd import', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "fmt"',
            '',
            'func check() {',
            '  log := thing.GetLogger()',
            '  _ = log',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) => f.kind === GO_BUG_RISK_FACT_KINDS.etcdGetLoggerMisuse,
          ),
        ).toHaveLength(0);
      });
    });

    describe('GO-W1004 — GORM SkipDefaultTransaction set to false', () => {
      it('flags SkipDefaultTransaction: false', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "gorm.io/gorm"',
            '',
            'func setup() {',
            '  db, _ := gorm.Open(nil, &gorm.Config{SkipDefaultTransaction: false})',
            '  _ = db',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.gormSkipDefaultTransaction,
        );
      });

      it('does not flag SkipDefaultTransaction: true', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func setup() {',
            '  cfg := Config{SkipDefaultTransaction: true}',
            '  _ = cfg',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) =>
              f.kind === GO_BUG_RISK_FACT_KINDS.gormSkipDefaultTransaction,
          ),
        ).toHaveLength(0);
      });
    });

    describe('GO-W1005 — GORM DryRun enabled', () => {
      it('flags DryRun: true', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "gorm.io/gorm"',
            '',
            'func setup() {',
            '  db, _ := gorm.Open(nil, &gorm.Config{DryRun: true})',
            '  _ = db',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.gormDryRunEnabled,
        );
      });

      it('does not flag DryRun: false', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'func setup() {',
            '  cfg := Config{DryRun: false}',
            '  _ = cfg',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) => f.kind === GO_BUG_RISK_FACT_KINDS.gormDryRunEnabled,
          ),
        ).toHaveLength(0);
      });
    });

    describe('GO-W1006 — reflect.MakeFunc usage', () => {
      it('flags reflect.MakeFunc call', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "reflect"',
            '',
            'func makeFn() {',
            '  fn := reflect.MakeFunc(reflect.TypeOf((func(int) int)(nil)), nil)',
            '  _ = fn',
            '}',
          ].join('\n'),
        });

        expect(facts.map((f) => f.kind)).toContain(
          GO_BUG_RISK_FACT_KINDS.reflectMakeFuncUsage,
        );
      });

      it('does not flag without MakeFunc', () => {
        const facts = collectGoBugRiskFacts({
          detector: 'go-detector',
          text: [
            'package main',
            '',
            'import "reflect"',
            '',
            'func getType() {',
            '  t := reflect.TypeOf(42)',
            '  _ = t',
            '}',
          ].join('\n'),
        });

        expect(
          facts.filter(
            (f) => f.kind === GO_BUG_RISK_FACT_KINDS.reflectMakeFuncUsage,
          ),
        ).toHaveLength(0);
      });
    });
  });

  describe('path suppression', () => {
    it('suppresses results in testdata/', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        path: 'testdata/sample.go',
        text: 'package main\nfunc main() { r.LoadHTMLGlob("bad") }\n',
      });

      expect(facts).toHaveLength(0);
    });

    it('suppresses results in _test.go', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        path: 'service_test.go',
        text: 'package main\nfunc main() { r.LoadHTMLGlob("bad") }\n',
      });

      expect(facts).toHaveLength(0);
    });

    it('suppresses results in vendor/', () => {
      const facts = collectGoBugRiskFacts({
        detector: 'go-detector',
        path: 'vendor/pkg/main.go',
        text: 'package main\nfunc main() { r.LoadHTMLGlob("bad") }\n',
      });

      expect(facts).toHaveLength(0);
    });
  });
});
