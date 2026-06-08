import {
  collectRustCorrectnessFacts,
  RUST_CORRECTNESS_FACT_KINDS,
} from './rust-correctness';

describe('rust-correctness collectors', () => {
  it('flags mutex guard held across await', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::sync::Mutex;',
        '',
        'async fn handler(data: Mutex<Vec<u8>>) {',
        '    let guard = data.lock().unwrap();',
        '    some_async().await;',
        '    let _ = guard.len();',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.mutexHeldAcrossAwait,
    );
  });

  it('does not flag mutex guard dropped before await', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::sync::Mutex;',
        '',
        'async fn handler(data: Mutex<Vec<u8>>) {',
        '    {',
        '        let guard = data.lock().unwrap();',
        '        let _ = guard.len();',
        '    }',
        '    some_async().await;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.mutexHeldAcrossAwait,
      ),
    ).toHaveLength(0);
  });

  it('flags std::thread::sleep inside async fn', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::time::Duration;',
        '',
        'async fn wait() {',
        '    std::thread::sleep(Duration::from_secs(1));',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.threadSleepInAsync,
    );
  });

  it('does not flag std::thread::sleep in sync fn', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::time::Duration;',
        '',
        'fn wait() {',
        '    std::thread::sleep(Duration::from_secs(1));',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.threadSleepInAsync,
      ),
    ).toHaveLength(0);
  });

  it('flags block_on inside async fn', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn run() {',
        '    tokio::runtime::Handle::current().block_on(async {});',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.blockOnInAsync,
    );
  });

  it('flags std::mem::forget on tokio::spawn handle', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn leak() {',
        '    std::mem::forget(tokio::spawn(async {}));',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.forgetJoinHandle,
    );
  });

  it('flags unbounded mpsc channel', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn channel() {',
        '    let (_tx, _rx) = tokio::sync::mpsc::unbounded_channel();',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.unboundedChannel,
    );
  });

  it('flags std::sync::Mutex in async fn', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn handler() {',
        '    let data: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());',
        '    let _ = data;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.stdMutexInAsyncFn,
    );
  });

  it('flags unchecked slice indexing with variable index', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn read(items: &[u8], index: usize) -> u8 {',
        '    items[index]',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.uncheckedIndex,
    );
  });

  it('does not flag literal slice indexing', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn read(items: &[u8]) -> u8 {',
        '    items[0]',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.uncheckedIndex,
      ),
    ).toHaveLength(0);
  });

  it('does not flag fallible get access', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn read(items: &[u8], index: usize) -> Option<u8> {',
        '    items.get(index).copied()',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.uncheckedIndex,
      ),
    ).toHaveLength(0);
  });

  it('returns no facts for suppressed test paths', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      path: 'tests/integration_test.rs',
      text: [
        'async fn wait() {',
        '    std::thread::sleep(std::time::Duration::from_secs(1));',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  // ── Batch 03: RS-E correctness collectors ──

  it('flags lowercase self in return type position', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn standalone() -> self {',
        '    self',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.selfNotSelfType,
    );
  });

  it('does not flag Self in method receivers', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'impl Foo {',
        '    fn method(&self) -> Self {',
        '        self.clone()',
        '    }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.selfNotSelfType,
      ),
    ).toHaveLength(0);
  });

  it('flags invalid regex literal with reversed range', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let _ = Regex::new("[z-a]");',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
    );
  });

  it('does not flag valid regex literal', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let _ = Regex::new("[a-z]");',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
      ),
    ).toHaveLength(0);
  });

  it('flags step_by(0)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let _ = (0..10).step_by(0);',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.stepByZero,
    );
  });

  it('does not flag step_by(1)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let _ = (0..10).step_by(1);',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.stepByZero,
      ),
    ).toHaveLength(0);
  });

  it('flags for loop over .next()', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let iter = [1,2,3].iter();',
        '    for x in iter.next() {',
        '        println!("{}", x);',
        '    }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.iterNextInForLoop,
    );
  });

  it('does not flag normal for loop', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    for x in 0..10 {',
        '        println!("{}", x);',
        '    }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.iterNextInForLoop,
      ),
    ).toHaveLength(0);
  });

  it('flags empty range with start > end', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    for _ in 42..21 { }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.emptyRangeExpression,
    );
  });

  it('does not flag ascending range', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    for _ in 0..10 { }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.emptyRangeExpression,
      ),
    ).toHaveLength(0);
  });

  it('flags erasing operation (x * 0)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test(x: i32) -> i32 {',
        '    x * 0',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.erasingOperation,
    );
  });

  it('flags erasing operation (x & 0)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test(flags: u32) -> u32 {',
        '    flags & 0',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.erasingOperation,
    );
  });

  it('does not flag non-erasing operation', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test(x: i32) -> i32 {',
        '    x * 2',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.erasingOperation,
      ),
    ).toHaveLength(0);
  });

  it('flags identical binary operands', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test(a: i32, b: i32) -> bool {',
        '    (a < b) || (a < b)',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.identicalBinaryOperands,
    );
  });

  it('does not flag different binary operands', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test(a: i32, b: i32) -> bool {',
        '    a < b || b < c',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.identicalBinaryOperands,
      ),
    ).toHaveLength(0);
  });

  it('flags multi-character char literal', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        "    let c = 'ab';",
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.syntaxError,
    );
  });

  it('does not flag valid char literal', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        "    let c = 'a';",
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.syntaxError,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 04: RS-E1009 through RS-E1016 ──

  it('flags mistyped integer suffix _32 (RS-E1009)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let value = 10_000_000_32;',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix,
    );
  });

  it('flags mistyped integer suffix _64 (RS-E1009)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let value = 100_64;',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix,
    );
  });

  it('does not flag proper _u32 suffix (RS-E1009)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let value = 10_000_000_u32;',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix,
      ),
    ).toHaveLength(0);
  });

  it('does not flag proper _i64 suffix (RS-E1009)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let value = 100_i64;',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix,
      ),
    ).toHaveLength(0);
  });

  it('does not flag other valid suffixes (RS-E1009)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let a = 10_u8; let b = 10_i16; let c = 10_usize; let d = 10_f32;',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.mistypedSuffix,
      ),
    ).toHaveLength(0);
  });

  it('flags mem::forget on reference (RS-E1010)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'std::mem::forget(&x);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.forgetDropOnReference,
    );
  });

  it('flags mem::drop on reference (RS-E1010)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'std::mem::drop(&y);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.forgetDropOnReference,
    );
  });

  it('does not flag mem::forget on owned value (RS-E1010)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'std::mem::forget(x);',
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.forgetDropOnReference,
      ),
    ).toHaveLength(0);
  });

  it('does not flag mem::drop on owned value (RS-E1010)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'std::mem::drop(y);',
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.forgetDropOnReference,
      ),
    ).toHaveLength(0);
  });

  it('flags mem::forget on non-reference value (RS-E1011)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let x = 42; std::mem::forget(x);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.forgetDropOnCopyType,
    );
  });

  it('flags mem::drop on non-reference value (RS-E1011)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'let x = 42; std::mem::drop(x);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.forgetDropOnCopyType,
    );
  });

  it('does not flag mem::forget on reference (RS-E1011 — covered by E1010)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'std::mem::forget(&x);',
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.forgetDropOnCopyType,
      ),
    ).toHaveLength(0);
  });

  it('flags != comparison with f32::NAN (RS-E1012)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if x != f32::NAN { }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nanComparison,
    );
  });

  it('flags == comparison with f64::NAN (RS-E1012)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if x == f64::NAN { }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nanComparison,
    );
  });

  it('flags f32::NAN == x pattern (RS-E1012)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if f32::NAN == x { }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nanComparison,
    );
  });

  it('does not flag .is_nan() call (RS-E1012)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if x.is_nan() { }',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.nanComparison,
      ),
    ).toHaveLength(0);
  });

  it('flags non-octal mode(755) (RS-E1013)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'builder.mode(755);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions,
    );
  });

  it('flags non-octal from_mode(493) (RS-E1013)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'Permissions::from_mode(493);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions,
    );
  });

  it('does not flag octal mode(0o755) (RS-E1013)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'builder.mode(0o755);',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions,
      ),
    ).toHaveLength(0);
  });

  it('does not flag octal from_mode(0o755) (RS-E1013)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'Permissions::from_mode(0o755);',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions,
      ),
    ).toHaveLength(0);
  });

  it('does not flag mode(0) (RS-E1013)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'builder.mode(0);',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.nonOctalPermissions,
      ),
    ).toHaveLength(0);
  });

  it('flags let _ = guard.lock() (RS-E1014)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let guard = std::sync::Mutex::new(0);',
        '    let _ = guard.lock();',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nonBindingLetOnLock,
    );
  });

  it('flags let _ = rwlock.read() (RS-E1014)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let rwlock = parking_lot::RwLock::new(0);',
        '    let _ = rwlock.read();',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.nonBindingLetOnLock,
    );
  });

  it('does not flag named binding let _lock = guard.lock() (RS-E1014)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let guard = std::sync::Mutex::new(0);',
        '    let _lock = guard.lock();',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.nonBindingLetOnLock,
      ),
    ).toHaveLength(0);
  });

  it('does not flag let _ = other_expr (RS-E1014)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn test() {',
        '    let _ = some_value;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_CORRECTNESS_FACT_KINDS.nonBindingLetOnLock,
      ),
    ).toHaveLength(0);
  });

  it('flags unit value from extend passed as argument (RS-E1015)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn foo<T: std::fmt::Debug>(t: T) {}',
        'let v = vec![1].extend(&[2, 3]);',
        'foo(v);',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.unitArgument,
    );
  });

  it('flags unit value from push passed as argument (RS-E1015)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn process(x: ()) {}',
        'let mut v = vec![1];',
        'let x = v.push(2);',
        'process(x);',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.unitArgument,
    );
  });

  it('flags { foo(); } == { bar(); } (RS-E1016)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if { std::println!("a"); } == { std::println!("b"); } { }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.unitComparison,
    );
  });

  it('flags { foo(); } != { bar(); } (RS-E1016)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if { std::println!("a"); } != { std::println!("b"); } { }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.unitComparison,
    );
  });

  it('does not flag blocks without semicolons (RS-E1016)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'if { foo() } == { bar() } { }',
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_CORRECTNESS_FACT_KINDS.unitComparison,
      ),
    ).toHaveLength(0);
  });

  // RS-E1026
  it('flags transmute integer to NonZero', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<i32, NonZeroI32>(x) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToNonZero,
    );
  });

  it('does not flag transmute between two integer types', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToNonZero,
      ),
    ).toHaveLength(0);
  });

  // RS-E1027
  it('flags transmute integer to fn ptr', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<usize, fn(i32) -> bool>(0) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteIntToFnPtr,
    );
  });

  it('does not flag transmute between two integer types (fn ptr)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteIntToFnPtr,
      ),
    ).toHaveLength(0);
  });

  // RS-E1028
  it('flags transmute integer literal to raw ptr', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<0usize, *const u8>(0) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteIntLitToRawPtr,
    );
  });

  it('does not flag transmute between two integer types (raw ptr)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteIntLitToRawPtr,
      ),
    ).toHaveLength(0);
  });

  // RS-E1029
  it('flags transmute f32 to reference', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<f32, &u8>(0.0_f32) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteFloatCharToRefOrPtr,
    );
  });

  it('does not flag transmute between numeric types', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<f32, u64>(0.0) }',
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteFloatCharToRefOrPtr,
      ),
    ).toHaveLength(0);
  });

  // RS-E1030
  it('flags transmute i32 to char', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, char>(x) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToChar,
    );
  });

  it('does not flag transmute between integer types (char)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteIntegerToChar,
      ),
    ).toHaveLength(0);
  });

  // RS-E1031
  it('flags transmute u32 to [u8; 4]', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, [u8; 4]>(x) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteNumberToSliceOrArray,
    );
  });

  it('does not flag transmute between integer types (array)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteNumberToSliceOrArray,
      ),
    ).toHaveLength(0);
  });

  // RS-E1032
  it('flags transmute (u32, u16) to [u8; 6]', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<(u32, u16), [u8; 6]>((0, 0)) }',
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.transmuteTupleToSliceOrArray,
    );
  });

  it('does not flag transmute between integer types (tuple)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: 'unsafe { std::mem::transmute::<u32, i64>(x) }',
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_CORRECTNESS_FACT_KINDS.transmuteTupleToSliceOrArray,
      ),
    ).toHaveLength(0);
  });

  // RS-E1034
  it('flags println! inside Display::fmt', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::fmt::{self, Display, Formatter};',
        'struct B;',
        'impl Display for B {',
        '    fn fmt(&self, f: &mut Formatter) -> fmt::Result {',
        '        println!("bad");',
        '        write!(f, "ok")',
        '    }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.printInDisplayImpl,
    );
  });

  it('does not flag write! inside Display::fmt', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'use std::fmt::{self, Display, Formatter};',
        'struct G;',
        'impl Display for G {',
        '    fn fmt(&self, f: &mut Formatter) -> fmt::Result {',
        '        write!(f, "ok")',
        '    }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.printInDisplayImpl,
      ),
    ).toHaveLength(0);
  });

  // RS-E1035: ignored future value

  it('flags async fn call in sync fn body (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch_data() -> String {',
        '    "data".to_string()',
        '}',
        '',
        'fn load() {',
        '    fetch_data();',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
    );
  });

  it('does not flag async fn call followed by .await (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch_data() -> String {',
        '    "data".to_string()',
        '}',
        '',
        'async fn load() {',
        '    fetch_data().await;',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('does not flag async fn call with let binding (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch_data() -> String {',
        '    "data".to_string()',
        '}',
        '',
        'fn load() {',
        '    let x = fetch_data();',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('does not flag async fn call with let underscore (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch_data() -> String {',
        '    "data".to_string()',
        '}',
        '',
        'fn load() {',
        '    let _ = fetch_data();',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('does not flag async fn call with return (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch_data() -> String {',
        '    "data".to_string()',
        '}',
        '',
        'fn load() -> impl std::future::Future<Output = String> {',
        '    fetch_data()',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('does not flag call in async fn body (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn inner() {}',
        'async fn outer() {',
        '    inner();',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('flags method-style async call in sync fn (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'struct S;',
        'impl S {',
        '    async fn fetch(&self) -> String {',
        '        "data".to_string()',
        '    }',
        '}',
        'fn load(s: &S) {',
        '    s.fetch();',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
    );
  });

  it('does not flag sync function calls (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn load_config() -> String {',
        '    "config".to_string()',
        '}',
        'fn load() {',
        '    load_config();',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('flags multiple calls to same async fn (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch() -> String {',
        '    "data".to_string()',
        '}',
        'fn load() {',
        '    fetch();',
        '    fetch();',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(2);
  });

  it('returns no facts for clean source (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'fn add(a: i32, b: i32) -> i32 {',
        '    a + b',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });

  it('does not flag async fn call passed as argument (RS-E1035)', () => {
    const facts = collectRustCorrectnessFacts({
      detector: 'rust-detector',
      text: [
        'async fn fetch() -> String {',
        '    "data".to_string()',
        '}',
        'fn run(f: impl std::future::Future) {}',
        'fn load() {',
        '    run(fetch());',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === RUST_CORRECTNESS_FACT_KINDS.ignoredFutureValue,
      ),
    ).toHaveLength(0);
  });
});
