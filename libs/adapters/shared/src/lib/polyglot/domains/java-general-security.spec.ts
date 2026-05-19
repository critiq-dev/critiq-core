import { collectJavaGeneralSecurityFacts } from './java-general-security';

describe('java-general-security collectors', () => {
  const detector = 'java-detector';

  it('flags Cipher.getInstance using ECB, RC4, or DES transformations', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'Cipher a = Cipher.getInstance("AES/ECB/PKCS5Padding");',
        'Cipher b = Cipher.getInstance("RC4");',
        'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
        'Cipher d = Cipher.getInstance("AES/GCM/NoPadding");',
        'Cipher e = Cipher.getInstance("DESede/CBC/PKCS5Padding");',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'java.security.insecure-cipher-mode',
      ),
    ).toHaveLength(3);
  });

  it('flags KeyPairGenerator RSA with weak key sizes', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
        'kpg.initialize(1024);',
        'KeyPairGenerator strong = KeyPairGenerator.getInstance("RSA");',
        'strong.initialize(2048);',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'java.security.weak-rsa-key-size'),
    ).toHaveLength(1);
  });

  it('flags SSLContext.getInstance with weak protocols', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'SSLContext a = SSLContext.getInstance("SSL");',
        'SSLContext b = SSLContext.getInstance("SSLv3");',
        'SSLContext c = SSLContext.getInstance("TLSv1.1");',
        'SSLContext d = SSLContext.getInstance("TLSv1.3");',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'java.security.insecure-ssl-context'),
    ).toHaveLength(3);
  });

  it('flags permissive CORS wildcards from Spring annotations and builders', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        '@CrossOrigin("*")',
        'public class A {}',
        '@CrossOrigin(origins = "https://example.com")',
        'public class B {}',
        'config.allowedOrigins("*");',
        'config.addAllowedOriginPattern("*");',
        'config.allowedOrigins("https://example.com");',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'java.security.permissive-cors'),
    ).toHaveLength(3);
  });

  it('flags trust-all TrustManager methods and TrustAllStrategy', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'class MyTrust implements X509TrustManager {',
        '  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {}',
        '  public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {}',
        '}',
        'SSLContextBuilder.create().loadTrustMaterial(null, TrustAllStrategy.INSTANCE);',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'java.security.trust-all-certificates',
      ),
    ).toHaveLength(3);
  });

  it('flags insecure network protocols in URL/URI constructors', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'URL bad = new URL("ftp://example.com/file");',
        'URL telnet = new URL("telnet://example.com");',
        'URI jar = URI.create("jar:http://example.com/archive.jar!/x");',
        'URL ok = new URL("https://example.com");',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'java.security.insecure-network-protocol',
      ),
    ).toHaveLength(3);
  });

  it('flags NullCipher usage', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'Cipher a = new NullCipher();',
        'Cipher b = Cipher.getInstance("Null");',
        'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'java.security.null-cipher'),
    ).toHaveLength(2);
  });

  it('flags JWT decode and parse calls without same-line verification', () => {
    const facts = collectJavaGeneralSecurityFacts({
      detector,
      text: [
        'DecodedJWT bad = JWT.decode(rawToken);',
        'DecodedJWT chained = JWT.decode(rawToken).verify(algorithm);',
        'Jws claims = Jwts.parser().parseClaimsJwt(rawToken);',
        'Jws verified = Jwts.parser().setSigningKey(key).parseClaimsJwt(rawToken);',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'java.security.jwt-without-verification',
      ),
    ).toHaveLength(2);
  });
});
