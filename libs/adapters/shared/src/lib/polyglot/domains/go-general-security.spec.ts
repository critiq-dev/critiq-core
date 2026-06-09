import {
  collectGoGeneralSecurityFacts,
  GO_GENERAL_SECURITY_FACT_KINDS,
} from './go-general-security';

describe('go-general-security collectors', () => {
  const detector = 'go-detector';

  it('flags jwt.Parse with nil keyfunc and jwt.ParseUnverified, jwt.Decode', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package handlers',
        '',
        'func auth(tokenStr string) {',
        '  token, _ := jwt.Parse(tokenStr, nil)',
        '  unverified, _ := jwt.ParseUnverified(tokenStr, &claims)',
        '  decoded, _ := jwt.Decode(tokenStr)',
        '  trusted, _ := jwt.Parse(tokenStr, keyFunc)',
        '  _, _, _ = token, unverified, decoded',
        '  _ = trusted',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'go.security.jwt-without-verification',
      ),
    ).toHaveLength(3);
  });

  it('flags tls.Config literals without MinVersion', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func setup() {',
        '  weak := &tls.Config{ServerName: "example.com"}',
        '  configured := &tls.Config{',
        '    ServerName: "example.com",',
        '    MinVersion: tls.VersionTLS12,',
        '  }',
        '  _, _ = weak, configured',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'go.security.tls-missing-min-version',
      ),
    ).toHaveLength(1);
  });

  it('flags insecure SSL protocol constants and literals', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func setup() {',
        '  cfg := &tls.Config{MinVersion: tls.VersionSSL30}',
        '  setProtocol("sslv3")',
        '  setProtocol("SSLv2")',
        '  ok := &tls.Config{MinVersion: tls.VersionTLS13}',
        '  _, _ = cfg, ok',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'go.security.insecure-ssl-protocol',
      ).length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('flags tls.Config CipherSuites containing weak cipher constants', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func setup() {',
        '  weak := &tls.Config{',
        '    MinVersion: tls.VersionTLS12,',
        '    CipherSuites: []uint16{',
        '      tls.TLS_RSA_WITH_RC4_128_SHA,',
        '      tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,',
        '    },',
        '  }',
        '  strong := &tls.Config{',
        '    MinVersion: tls.VersionTLS12,',
        '    CipherSuites: []uint16{',
        '      tls.TLS_AES_128_GCM_SHA256,',
        '      tls.TLS_AES_256_GCM_SHA384,',
        '    },',
        '  }',
        '  _, _ = weak, strong',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'go.security.weak-tls-cipher'),
    ).toHaveLength(1);
  });

  it('flags pprof handler registration and blank pprof import', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import (',
        '  "net/http"',
        '  _ "net/http/pprof"',
        ')',
        '',
        'func register() {',
        '  http.Handle("/debug/pprof/", http.DefaultServeMux)',
        '  http.HandleFunc("/debug/pprof/profile", handlePprof)',
        '  http.HandleFunc("/healthz", handleHealthz)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'go.security.pprof-exposed').length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('flags bcrypt.GenerateFromPassword with weak cost values', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package security',
        '',
        'func hash(pwd []byte) {',
        '  _, _ = bcrypt.GenerateFromPassword(pwd, 4)',
        '  _, _ = bcrypt.GenerateFromPassword(pwd, 12)',
        '  _, _ = bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)',
        '  _, _ = bcrypt.HashPassword(pwd, 6)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'go.security.weak-bcrypt-cost'),
    ).toHaveLength(2);
  });

  it('flags math/rand seed calls when math/rand is imported', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import (',
        '  "math/rand"',
        '  "time"',
        ')',
        '',
        'func setup() {',
        '  rand.Seed(time.Now().UnixNano())',
        '  rand.Seed(42)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'go.security.insecure-rand-seed'),
    ).toHaveLength(2);
  });

  it('does not flag math/rand seed when math/rand is not imported', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func setup() {',
        '  rand.Seed(42)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'go.security.insecure-rand-seed'),
    ).toHaveLength(0);
  });

  it('returns no facts for clean Go source', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import (',
        '  "crypto/rand"',
        '  "crypto/tls"',
        ')',
        '',
        'func main() {',
        '  cfg := &tls.Config{MinVersion: tls.VersionTLS13}',
        '  _ = cfg',
        '  _ = rand.Reader',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('flags bind-all listens on stdlib and framework entrypoints', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func boot() {',
        '  http.ListenAndServe("0.0.0.0:8080", nil)',
        '  net.Listen("tcp", "[::]:9090")',
        '  r.Run("0.0.0.0:7000")',
        '  app.Listen(":3000")',
        '  e.Start("127.0.0.1:4040")',
        '}',
      ].join('\n'),
    });

    const bindFacts = facts.filter(
      (fact) => fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces,
    );
    expect(bindFacts.length).toBeGreaterThanOrEqual(3);
  });

  it('skips bind-all collector when no all-interface literal is present', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func boot() {',
        '  http.ListenAndServe(":8080", nil)',
        '  net.Listen("tcp", "127.0.0.1:9090")',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces,
      ),
    ).toHaveLength(0);
  });

  it('flags imports of the unsafe package', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "unsafe"',
        '',
        'import (',
        '  "fmt"',
        '  "unsafe"',
        '  unsafe2 "unsafe"',
        ')',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.unsafePackageImport,
      ).length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('does not flag the unsafe literal outside an import block', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'var note = "unsafe"',
        '',
        'func main() {',
        '  _ = "unsafe"',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.unsafePackageImport,
      ),
    ).toHaveLength(0);
  });

  it('flags ssh.InsecureIgnoreHostKey usage', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func config() *ssh.ClientConfig {',
        '  return &ssh.ClientConfig{',
        '    HostKeyCallback: ssh.InsecureIgnoreHostKey(),',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.insecureSshHostKey,
      ),
    ).toHaveLength(1);
  });

  it('flags ioutil.TempFile and ioutil.TempDir but not os.CreateTemp', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func make() {',
        '  f, _ := ioutil.TempFile("", "report-")',
        '  d, _ := ioutil.TempDir("", "build-")',
        '  g, _ := os.CreateTemp("", "ok-*.tmp")',
        '  _ = f',
        '  _ = d',
        '  _ = g',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.insecureTempFile,
      ),
    ).toHaveLength(2);
  });

  it('flags rsa.GenerateKey with size below 2048 but allows 2048+', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'func generate() {',
        '  _, _ = rsa.GenerateKey(rand.Reader, 1024)',
        '  _, _ = rsa.GenerateKey(rand.Reader, 2048)',
        '  _, _ = rsa.GenerateMultiPrimeKey(rand.Reader, 2, 1024)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.weakRsaKeySize,
      ),
    ).toHaveLength(2);
  });

  it('flags imports of weak crypto packages', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "crypto/md5"',
        '',
        'import (',
        '  "crypto/des"',
        '  "crypto/rc4"',
        '  hash "crypto/sha1"',
        '  "crypto/sha256"',
        ')',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === GO_GENERAL_SECURITY_FACT_KINDS.weakCryptoImport,
      ),
    ).toHaveLength(4);
  });

  it('skips all collectors when path is a test source', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      path: 'cmd/server/main_test.go',
      text: [
        'package main',
        '',
        'import "unsafe"',
        '',
        'func boot() {',
        '  http.ListenAndServe("0.0.0.0:8080", nil)',
        '  ssh.InsecureIgnoreHostKey()',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('flags io.Copy with decompression reader (decompression bomb)', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import (',
        '  "compress/gzip"',
        '  "io"',
        '  "os"',
        ')',
        '',
        'func decompress() {',
        '  f, _ := os.Open("data.gz")',
        '  zr, _ := gzip.NewReader(f)',
        '  io.Copy(os.Stdout, zr)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.decompressionBomb),
    ).toHaveLength(1);
  });

  it('does not flag io.Copy with limited reader', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import (',
        '  "compress/gzip"',
        '  "io"',
        '  "os"',
        ')',
        '',
        'func safeDecompress() {',
        '  f, _ := os.Open("data.gz")',
        '  zr, _ := gzip.NewReader(f)',
        '  io.CopyN(os.Stdout, zr, 1024)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.decompressionBomb),
    ).toHaveLength(0);
  });

  it('flags http.FileServer with http.Dir root path', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "net/http"',
        '',
        'func serve() {',
        '  http.FileServer(http.Dir("/"))',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.httpDirPathTraversal),
    ).toHaveLength(1);
  });

  it('does not flag http.FileServer with relative Dir', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "net/http"',
        '',
        'func serve() {',
        '  http.FileServer(http.Dir("./static"))',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.httpDirPathTraversal),
    ).toHaveLength(0);
  });

  it('flags os.WriteFile with permission > 0600', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func write() {',
        '  os.WriteFile("/tmp/f", []byte("x"), 0744)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.weakFilePermission),
    ).toHaveLength(1);
  });

  it('does not flag os.WriteFile with permission 0600', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func write() {',
        '  os.WriteFile("/tmp/f", []byte("x"), 0600)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.weakFilePermission),
    ).toHaveLength(0);
  });

  it('flags defer f.Close() without Sync in os-imported files', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func write() {',
        '  f, _ := os.Create("/tmp/f")',
        '  defer f.Close()',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.unsafeDeferClose),
    ).toHaveLength(1);
  });

  it('does not flag defer f.Close() with f.Sync()', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "os"',
        '',
        'func write() {',
        '  f, _ := os.Create("/tmp/f")',
        '  defer f.Close()',
        '  f.Sync()',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.unsafeDeferClose),
    ).toHaveLength(0);
  });

  it('flags db.ExecContext with fmt.Sprintf using user input (tainted sink)', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "fmt"',
        '',
        'func query(db *sql.DB, input string) {',
        '  db.ExecContext(ctx, fmt.Sprintf("SELECT * FROM users WHERE id = %s", input))',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.taintedValueSink),
    ).toHaveLength(1);
  });

  it('does not flag parameterized db query', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "fmt"',
        '',
        'func query(db *sql.DB) {',
        '  db.ExecContext(ctx, "SELECT * FROM users WHERE id = ?", id)',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.taintedValueSink),
    ).toHaveLength(0);
  });

  it('flags incomplete hostname regex with unanchored pattern', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "regexp"',
        '',
        'func validate() {',
        '  re := regexp.MustCompile("[a-zA-Z0-9.-]+")',
        '  _ = re',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.incompleteHostnameRegex,
      ),
    ).toHaveLength(1);
  });

  it('flags regexp.Compile with bare hostname pattern', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "regexp"',
        '',
        'func validate() {',
        '  re, _ := regexp.Compile("google.com")',
        '  _ = re',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.incompleteHostnameRegex,
      ),
    ).toHaveLength(1);
  });

  it('does not flag properly anchored hostname regex', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "regexp"',
        '',
        'func validate() {',
        '  re := regexp.MustCompile("^[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$")',
        '  _ = re',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.incompleteHostnameRegex,
      ),
    ).toHaveLength(0);
  });

  it('does not flag non-hostname regex patterns', () => {
    const facts = collectGoGeneralSecurityFacts({
      detector,
      text: [
        'package main',
        '',
        'import "regexp"',
        '',
        'func validate() {',
        '  re := regexp.MustCompile("\\\\d{4}-\\\\d{2}-\\\\d{2}")',
        '  _ = re',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === GO_GENERAL_SECURITY_FACT_KINDS.incompleteHostnameRegex,
      ),
    ).toHaveLength(0);
  });
});
