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
});
