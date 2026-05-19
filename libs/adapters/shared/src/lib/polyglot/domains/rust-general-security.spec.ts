import {
  collectRustGeneralSecurityFacts,
  RUST_GENERAL_SECURITY_FACT_KINDS,
} from './rust-general-security';

describe('rust-general-security collectors', () => {
  const detector = 'rust-detector';

  it('flags bind-all listens on common Rust network entrypoints', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'use std::net::TcpListener;',
        '',
        'fn boot() {',
        '  let _ = TcpListener::bind("0.0.0.0:8080");',
        '  let _ = std::net::TcpListener::bind("[::]:9090");',
        '  let _ = SocketAddr::from("0.0.0.0:7000".parse().unwrap());',
        '  let _ = TcpListener::bind("127.0.0.1:4040");',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces,
      ).length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('flags rustls ClientConfig without min protocol version', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn setup() -> rustls::ClientConfig {',
        '  rustls::ClientConfig {',
        '    root_store: RootCertStore::empty(),',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.tlsMissingMinVersion,
      ),
    ).toHaveLength(1);
  });

  it('flags insecure SSL/TLS protocol constants', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn setup() {',
        '  let _ = Protocol::SSLv3;',
        '  let _ = TlsVersion::TLSv1_0;',
        '  let _ = TlsVersion::TLSv1_2;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.insecureSslProtocol,
      ),
    ).toHaveLength(2);
  });

  it('flags weak TLS cipher suite names', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn setup() {',
        '  let weak = CipherSuite::TLS_RSA_WITH_RC4_128_SHA;',
        '  let suites = vec!["TLS_RSA_WITH_3DES_EDE_CBC_SHA"];',
        '  let strong = CipherSuite::TLS_AES_128_GCM_SHA256;',
        '  let _ = (weak, suites, strong);',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.weakTlsCipher,
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it('flags JWT decode without verification key', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn auth(token: &str) {',
        '  let _ = jsonwebtoken::decode::<Claims>(token, &Validation::default());',
        '  let _ = dangerous_insecure_decode(token);',
        '  let _ = Validation::insecure_disable_signature_validation();',
        '  let key = DecodingKey::from_secret(b"secret");',
        '  let _ = decode::<Claims>(token, &key, &Validation::default());',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.jwtWithoutVerification,
      ).length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('flags insecure temp file helpers and predictable /tmp paths', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn make() {',
        '  let _ = tempfile::tempfile();',
        '  let _ = NamedTempFile::new();',
        '  let _ = std::fs::File::create("/tmp/report.txt");',
        '  let _ = std::fs::File::create("/tmp/ok-*.tmp");',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.insecureTempFile,
      ),
    ).toHaveLength(3);
  });

  it('flags disabled SSH host key verification', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn connect(session: &mut ssh2::Session) {',
        '  session.set_hostkey_check(false);',
        '  session.check_host_key(false);',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.insecureSshHostKey,
      ),
    ).toHaveLength(2);
  });

  it('flags weak crypto crate imports', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'use md5;',
        'use sha1::Sha1;',
        'extern crate rc4;',
        'use crypto::sha256;',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.weakCryptoImport,
      ),
    ).toHaveLength(3);
  });

  it('flags RSA key generation below 2048 bits', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn generate() {',
        '  let _ = RsaPrivateKey::new(&mut rng, 1024);',
        '  let _ = RsaPrivateKey::new(&mut rng, 2048);',
        '  let _ = Rsa::generate(512);',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.weakRsaKeySize,
      ),
    ).toHaveLength(2);
  });

  it('flags shell command spawn with -c', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn run(cmd: &str) {',
        '  let _ = Command::new("sh").arg("-c").arg(cmd);',
        '  let _ = Command::new("/bin/bash").args(["-c", cmd]);',
        '  let _ = Command::new("git").arg("status");',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.shellCommandSpawn,
      ),
    ).toHaveLength(2);
  });

  it('flags serde_yaml untyped deserialization entrypoints', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'fn load(input: &str, reader: impl Read) {',
        '  let _ = serde_yaml::from_str(input);',
        '  let _ = serde_yaml::from_reader(reader);',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.insecureYamlLoad,
      ),
    ).toHaveLength(2);
  });

  it('flags panic and unwrap in async fn bodies', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'async fn handler() {',
        '  panic!("boom");',
        '  let value = fetch().unwrap();',
        '  let _ = value;',
        '}',
        '',
        'fn sync_handler() {',
        '  panic!("ignored");',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === RUST_GENERAL_SECURITY_FACT_KINDS.panicInAsyncHandler,
      ),
    ).toHaveLength(2);
  });

  it('returns no facts for clean Rust source', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      text: [
        'use sha2::Sha256;',
        '',
        'async fn handler() -> Result<(), Error> {',
        '  let listener = TcpListener::bind("127.0.0.1:8080")?;',
        '  let _ = listener;',
        '  Ok(())',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('skips all collectors when path is a test source', () => {
    const facts = collectRustGeneralSecurityFacts({
      detector,
      path: 'src/handlers_test.rs',
      text: [
        'async fn handler() {',
        '  panic!("boom");',
        '  let _ = TcpListener::bind("0.0.0.0:8080");',
        '  use md5;',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
