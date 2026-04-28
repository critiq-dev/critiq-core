import { goSourceAdapter } from './go';

describe('goSourceAdapter', () => {
  it('analyzes valid Go source', () => {
    const result = goSourceAdapter.analyze(
      'service.go',
      [
        'package main',
        '',
        'func main() {',
        '  println("ok")',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('go');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Go source', () => {
    const result = goSourceAdapter.analyze(
      'broken.go',
      [
        'package main',
        '',
        'func main( {',
        '  println("oops")',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = goSourceAdapter.analyze(
      'service.go',
      [
        'package main',
        '',
        'import (',
        '  "encoding/json"',
        '  "fmt"',
        '  "log"',
        '  "os"',
        '  "os/exec"',
        ')',
        '',
        'func handler(r Request, db DB) {',
        '  apiKey := "sk_live_12345678"',
        '  reportName := r.URL.Query().Get("report")',
        '  _, _ = os.ReadFile(reportName)',
        '  _, _ = exec.Command("sh", "-c", reportName).Output()',
        '  query := fmt.Sprintf("SELECT * FROM users WHERE email = \'%s\'", reportName)',
        '  db.Query(query)',
        '  payload := r.FormValue("payload")',
        '  var decoded map[string]string',
        '  _ = json.Unmarshal([]byte(payload), &decoded)',
        '  authToken := r.Header.Get("Authorization")',
        '  log.Printf("email=%s auth=%s", reportName, authToken)',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
      'security.request-path-file-read',
      'security.command-execution-with-request-input',
      'security.sql-interpolation',
      'security.unsafe-deserialization',
      'security.sensitive-data-in-logs-and-telemetry',
    ]);
  });

  it('emits transport and crypto security facts', () => {
    const result = goSourceAdapter.analyze(
      'transport.go',
      [
        'package main',
        '',
        'import (',
        '  "crypto/md5"',
        '  "crypto/tls"',
        '  "net/http"',
        ')',
        '',
        'func main() {',
        '  _, _ = http.Get("http://api.example.com/users")',
        '  transport := &http.Transport{',
        '    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},',
        '  }',
        '  _, _ = md5.Sum([]byte("payload"))',
        '  _ = transport',
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
});
