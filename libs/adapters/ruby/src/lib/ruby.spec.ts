import { rubySourceAdapter } from './ruby';

describe('rubySourceAdapter', () => {
  it('analyzes valid Ruby source', () => {
    const result = rubySourceAdapter.analyze(
      'app.rb',
      [
        'def run',
        '  puts "ok"',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('ruby');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Ruby source', () => {
    const result = rubySourceAdapter.analyze(
      'broken.rb',
      [
        'def run(',
        '  puts "oops"',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = rubySourceAdapter.analyze(
      'service.rb',
      [
        'API_SECRET = "sk_live_12345678"',
        'report_name = params[:report]',
        'logger.info("token=#{params[:token]}")',
        'File.read(report_name)',
        'system(report_name)',
        'query = "SELECT * FROM reports WHERE name = \'#{report_name}\'"',
        'connection.execute(query)',
        'payload = params[:payload]',
        'Marshal.load(payload)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
      'security.sensitive-data-in-logs-and-telemetry',
      'security.request-path-file-read',
      'security.command-execution-with-request-input',
      'security.sql-interpolation',
      'security.unsafe-deserialization',
    ]);
  });

  it('emits transport and crypto security facts', () => {
    const result = rubySourceAdapter.analyze(
      'transport.rb',
      [
        'URI.open("http://api.example.com/users")',
        'http.verify_mode = OpenSSL::SSL::VERIFY_NONE',
        'Digest::SHA1.hexdigest("payload")',
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
});
