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

});
