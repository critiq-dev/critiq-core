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
      'go.security.weak-crypto-import',
      'security.insecure-http-transport',
      'security.tls-verification-disabled',
      'go.security.tls-missing-min-version',
      'security.weak-hash-algorithm',
    ]);
  });

  it('emits general security facts for JWT, TLS, pprof, bcrypt, and rand', () => {
    const result = goSourceAdapter.analyze(
      'security.go',
      [
        'package main',
        '',
        'import (',
        '  "crypto/tls"',
        '  "math/rand"',
        '  "net/http"',
        '  _ "net/http/pprof"',
        ')',
        '',
        'func setup() {',
        '  cfg := &tls.Config{ServerName: "x"}',
        '  weakSsl := &tls.Config{MinVersion: tls.VersionSSL30}',
        '  weakCiphers := &tls.Config{',
        '    MinVersion:   tls.VersionTLS12,',
        '    CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},',
        '  }',
        '  http.Handle("/debug/pprof/", http.DefaultServeMux)',
        '  _, _ = bcrypt.GenerateFromPassword([]byte("a"), 4)',
        '  rand.Seed(42)',
        '  _, _ = jwt.Parse("t", nil)',
        '  _, _ = jwt.ParseUnverified("t", &claims)',
        '  _, _ = jwt.Decode("t")',
        '  _, _, _ = cfg, weakSsl, weakCiphers',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds =
      result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind) ?? [];
    expect(kinds).toContain('go.security.jwt-without-verification');
    expect(kinds).toContain('go.security.tls-missing-min-version');
    expect(kinds).toContain('go.security.insecure-ssl-protocol');
    expect(kinds).toContain('go.security.weak-tls-cipher');
    expect(kinds).toContain('go.security.pprof-exposed');
    expect(kinds).toContain('go.security.weak-bcrypt-cost');
    expect(kinds).toContain('go.security.insecure-rand-seed');
  });

  it('emits baseline general security facts (bind-all, unsafe, ssh, temp, rsa, crypto)', () => {
    const result = goSourceAdapter.analyze(
      'baseline.go',
      [
        'package main',
        '',
        'import (',
        '  "crypto/md5"',
        '  "unsafe"',
        ')',
        '',
        'func boot() {',
        '  http.ListenAndServe("0.0.0.0:8080", nil)',
        '  ssh.InsecureIgnoreHostKey()',
        '  _, _ = ioutil.TempFile("", "x-")',
        '  _, _ = rsa.GenerateKey(rand.Reader, 1024)',
        '  _ = unsafe.Sizeof(0)',
        '  _ = md5.New()',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds =
      result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind) ?? [];
    expect(kinds).toContain('go.security.bind-all-interfaces');
    expect(kinds).toContain('go.security.unsafe-package-import');
    expect(kinds).toContain('go.security.insecure-ssh-host-key');
    expect(kinds).toContain('go.security.insecure-temp-file');
    expect(kinds).toContain('go.security.weak-rsa-key-size');
    expect(kinds).toContain('go.security.weak-crypto-import');
  });


  it('emits shared performance hygiene facts', () => {
    const result = goSourceAdapter.analyze(
      'service_test.go',
      [
        'package main',
        'func test(items []string) {',
        '  Promise.all(items.map(func(x string) {}))',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toContain(
      'go.performance.no-unbounded-concurrency',
    );
  });

});
