import { rustSourceAdapter } from './rust';

describe('rustSourceAdapter', () => {
  it('analyzes valid Rust source', () => {
    const result = rustSourceAdapter.analyze(
      'main.rs',
      [
        'fn main() {',
        '    println!("ok");',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('rust');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Rust source', () => {
    const result = rustSourceAdapter.analyze(
      'broken.rs',
      [
        'fn main( {',
        '    println!("oops");',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = rustSourceAdapter.analyze(
      'service.rs',
      [
        'const API_SECRET: &str = "sk_live_12345678";',
        'fn handle(req: Request, client: Client) {',
        '    let report = req.query_string();',
        '    println!("token={}", req.headers().get("Authorization"));',
        '    let _ = std::fs::read_to_string(report);',
        '    let _ = std::process::Command::new("sh").arg(report).output();',
        '    let query = format!("SELECT * FROM reports WHERE name = \'{}\'", report);',
        '    client.query(query);',
        '    let payload = req.query_string();',
        '    let _ = serde_json::from_str(payload);',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual(
      expect.arrayContaining([
        'security.hardcoded-credentials',
        'security.sensitive-data-in-logs-and-telemetry',
        'security.request-path-file-read',
        'security.command-execution-with-request-input',
        'security.sql-interpolation',
        'security.unsafe-deserialization',
      ]),
    );
  });

  it('emits transport and crypto security facts', () => {
    const result = rustSourceAdapter.analyze(
      'transport.rs',
      [
        'fn fetch() {',
        '    reqwest::get("http://api.example.com/users");',
        '    Client::builder().danger_accept_invalid_certs(true);',
        '    md5::compute("payload");',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.insecure-http-transport',
      'security.tls-verification-disabled',
      'security.weak-hash-algorithm',
    ]);
  });


  it('emits shared performance hygiene facts', () => {
    const result = rustSourceAdapter.analyze(
      'service_test.rs',
      [
        'fn test(items: Vec<String>) {',
        '  let _ = futures::future::join_all(items.iter().map(task));',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toContain(
      'rust.performance.no-unbounded-concurrency',
    );
  });

  it('emits general Rust security facts', () => {
    const result = rustSourceAdapter.analyze(
      'server.rs',
      [
        'use md5;',
        '',
        'async fn boot() {',
        '  let _ = std::net::TcpListener::bind("0.0.0.0:8080");',
        '  let _ = Command::new("sh").arg("-c").arg("echo hi");',
        '  let _ = serde_yaml::from_str("{a: 1}");',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual(
      expect.arrayContaining([
        'rust.security.bind-all-interfaces',
        'rust.security.weak-crypto-import',
        'rust.security.shell-command-spawn',
        'rust.security.insecure-yaml-load',
      ]),
    );
  });

  it('skips general Rust security facts in test paths', () => {
    const result = rustSourceAdapter.analyze(
      'src/server_test.rs',
      [
        'async fn boot() {',
        '  panic!("test only");',
        '  let _ = std::net::TcpListener::bind("0.0.0.0:8080");',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some((fact) =>
        fact.kind.startsWith('rust.security.'),
      ),
    ).toBe(false);
  });

  it('emits batch-03 correctness facts', () => {
    const result = rustSourceAdapter.analyze('bug_risk.rs', [
      'fn return_self() -> self {',
      '    self',
      '}',
      '',
      'fn bad_regex() {',
      '    let _ = regex::Regex::new("[z-a]");',
      '}',
      '',
      'fn bad_step() {',
      '    let _ = (0..10).step_by(0);',
      '}',
      '',
      'fn iter_next_loop() {',
      '    let iter = [1,2,3].iter();',
      '    for x in iter.next() {',
      '        println!("{}", x);',
      '    }',
      '}',
      '',
      'fn empty_range() {',
      '    for _ in 42..21 { }',
      '}',
    ].join('\n'));

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toEqual(expect.arrayContaining([
      'rust.correctness.self-not-self-type',
      'rust.correctness.invalid-regex-literal',
      'rust.correctness.step-by-zero',
      'rust.correctness.iter-next-in-for-loop',
      'rust.correctness.empty-range-expression',
    ]));
  });

  it('emits batch-07 security facts (unsafe code, invisible unicode, global permissions)', () => {
    const result = rustSourceAdapter.analyze('security.rs', [
      'fn ptr_cast(ptr: *const u8) -> *mut u8 {',
      '    unsafe { ptr as *mut u8 }',
      '}',
      '',
      'fn slice_ptr(data: &[u8]) -> *const u8 {',
      '    &data[..] as *const u8',
      '}',
      '',
      'fn check(user: &str) -> bool {',
      '    if\u200B(user == "admin") { return true; }',
      '    false',
      '}',
      '',
      'use std::os::unix::fs::PermissionsExt;',
      'fn set_perm(path: &str) {',
      '    std::fs::set_permissions(path, PermissionsExt::from_mode(0o777));',
      '}',
      '',
      'fn test_regex(input: &str) -> bool {',
      '    let re = regex::Regex::new(r"((a+)+)").unwrap();',
      '    re.is_match(input)',
      '}',
    ].join('\n'));

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toEqual(expect.arrayContaining([
      'rust.security.const-to-mut-ptr',
      'rust.security.raw-slice-to-ptr',
      'rust.security.invisible-unicode',
      'rust.security.global-write-permission',
      'rust.security.potentially-vulnerable-regex',
    ]));
  });

  it('emits batch-05 transmute and print-in-display correctness facts', () => {
    const result = rustSourceAdapter.analyze('transmute.rs', [
      'fn transmute_bugs(x: i32) {',
      '    let _y: NonZeroI32 = unsafe { std::mem::transmute::<i32, NonZeroI32>(x) };',
      '    let _c: char = unsafe { std::mem::transmute::<u32, char>(x as u32) };',
      '    let _arr: [u8; 4] = unsafe { std::mem::transmute::<i32, [u8; 4]>(x) };',
      '    let _tup_arr: [u8; 4] = unsafe { std::mem::transmute::<(u16, u8), [u8; 4]>((0, 0)) };',
      '    let _p: fn(i32) -> bool = unsafe { std::mem::transmute::<usize, fn(i32) -> bool>(0usize) };',
      '    let _q: *const u8 = unsafe { std::mem::transmute::<usize, *const u8>(0usize) };',
      '    let _r: &u8 = unsafe { std::mem::transmute::<f32, &u8>(0.0f32) };',
      '}',
      '',
      'use std::fmt::{self, Display, Formatter};',
      'struct BadDisplay;',
      'impl Display for BadDisplay {',
      '    fn fmt(&self, f: &mut Formatter) -> fmt::Result {',
      '        println!("formatting");',
      '        write!(f, "...")',
      '    }',
      '}',
    ].join('\n'));

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toEqual(expect.arrayContaining([
      'rust.correctness.transmute-integer-to-nonzero',
      'rust.correctness.transmute-integer-to-char',
      'rust.correctness.transmute-number-to-slice-or-array',
      'rust.correctness.transmute-tuple-to-slice-or-array',
      'rust.correctness.print-in-display-impl',
      'rust.correctness.transmute-int-to-fn-ptr',
      'rust.correctness.transmute-int-lit-to-raw-ptr',
      'rust.correctness.transmute-float-char-to-ref-or-ptr',
    ]));
  });
});
