import { pythonSourceAdapter } from './python';

describe('pythonSourceAdapter', () => {
  it('analyzes valid Python source', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'def main():',
        '    print("ok")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('python');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Python source', () => {
    const result = pythonSourceAdapter.analyze(
      'broken.py',
      [
        'def main(',
        '    print("oops")',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'import json',
        'import logging',
        'import pickle',
        'import subprocess',
        '',
        'logger = logging.getLogger(__name__)',
        'API_SECRET = "sk_live_12345678"',
        '',
        '@app.get("/reports/<path:report_name>")',
        'def get_report(report_name: str):',
        '    target = REPORT_ROOT / report_name',
        '    logger.info("email=%s token=%s", report_name, request.headers.get("Authorization"))',
        '    subprocess.run(report_name, shell=True)',
        '    query = f"SELECT * FROM reports WHERE name = \'{report_name}\'"',
        '    cursor.execute(query)',
        '    payload = request.data',
        '    config = pickle.loads(payload)',
        '    return target.read_text(encoding="utf-8")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
      'security.sensitive-data-in-logs-and-telemetry',
      'security.command-execution-with-request-input',
      'security.sql-interpolation',
      'security.unsafe-deserialization',
      'security.request-path-file-read',
    ]);
  });

  it('emits transport and crypto security facts', () => {
    const result = pythonSourceAdapter.analyze(
      'transport.py',
      [
        'import hashlib',
        'import requests',
        'import ssl',
        '',
        'def fetch(data: bytes):',
        '    requests.get("http://api.example.com/users")',
        '    requests.get("https://api.example.com/users", verify=False)',
        '    digest = hashlib.md5(data).hexdigest()',
        '    context = ssl._create_unverified_context()',
        '    return digest, context',
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
      'security.tls-verification-disabled',
    ]);
  });
});
