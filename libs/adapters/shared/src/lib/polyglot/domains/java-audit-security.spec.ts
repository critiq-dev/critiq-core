import {
  collectJavaAuditSecurityFacts,
  JAVA_AUDIT_SECURITY_FACT_KINDS,
} from './java-audit-security';

describe('collectJavaAuditSecurityFacts', () => {
  const detector = 'java-detector';
  const path = 'src/main/java/demo/Demo.java';

  it('skips non-java sources', () => {
    const facts = collectJavaAuditSecurityFacts({
      text: 'DocumentBuilderFactory.newInstance();',
      path: 'src/main/resources/application.yml',
      detector,
    });

    expect(facts).toHaveLength(0);
  });

  it('skips test sources', () => {
    const facts = collectJavaAuditSecurityFacts({
      text: 'DocumentBuilderFactory.newInstance();',
      path: 'src/test/java/demo/DemoTest.java',
      detector,
    });

    expect(facts).toHaveLength(0);
  });

  it('flags Jackson default typing toggles', () => {
    const text = [
      'class Mapper {',
      '  ObjectMapper build() {',
      '    ObjectMapper mapper = new ObjectMapper();',
      '    mapper.enableDefaultTyping();',
      '    mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance);',
      '    return mapper;',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.unsafeJacksonDeserialization,
      ),
    ).toHaveLength(2);
  });

  it('flags @JsonTypeInfo with Id.CLASS but not Id.NAME', () => {
    const text = [
      '@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)',
      'class A {}',
      '@JsonTypeInfo(use = Id.MINIMAL_CLASS, include = As.PROPERTY)',
      'class B {}',
      '@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = As.PROPERTY, property = "type")',
      'class C {}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.unsafeJacksonDeserialization,
      ),
    ).toHaveLength(2);
  });

  it('flags DocumentBuilderFactory without secure processing', () => {
    const text = [
      'class P {',
      '  void p() throws Exception {',
      '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();',
      '    f.newDocumentBuilder().parse(input);',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.xxeDocumentBuilder,
      ),
    ).toHaveLength(1);
  });

  it('skips DocumentBuilderFactory when secure processing is enabled', () => {
    const text = [
      'class P {',
      '  void p() throws Exception {',
      '    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();',
      '    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.xxeDocumentBuilder,
      ),
    ).toHaveLength(0);
  });

  it('flags XMLInputFactory without external entity hardening', () => {
    const text = [
      'class P {',
      '  void p() throws Exception {',
      '    XMLInputFactory f = XMLInputFactory.newInstance();',
      '    f.createXMLStreamReader(stream);',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.xxeXmlInputFactory,
      ),
    ).toHaveLength(1);
  });

  it('skips XMLInputFactory when SUPPORT_DTD is disabled', () => {
    const text = [
      'class P {',
      '  void p() throws Exception {',
      '    XMLInputFactory f = XMLInputFactory.newInstance();',
      '    f.setProperty(XMLInputFactory.SUPPORT_DTD, false);',
      '    f.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.xxeXmlInputFactory,
      ),
    ).toHaveLength(0);
  });

  it('flags Hibernate Session.createQuery with concatenation', () => {
    const text = [
      'class Repo {',
      '  Session session;',
      '  Object find(String email) {',
      '    return session.createQuery("from User u where u.email = \'" + email + "\'").list();',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.hibernateSqlConcatenation,
      ),
    ).toHaveLength(1);
  });

  it('flags Hibernate createNativeQuery via getCurrentSession with String.format', () => {
    const text = [
      'class Repo {',
      '  SessionFactory sessionFactory;',
      '  Object find(String email) {',
      '    return sessionFactory.getCurrentSession()',
      '        .createNativeQuery(String.format("select * from users where email = \'%s\'", email))',
      '        .getResultList();',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.hibernateSqlConcatenation,
      ),
    ).toHaveLength(1);
  });

  it('skips Hibernate createQuery using setParameter', () => {
    const text = [
      'class Repo {',
      '  Session session;',
      '  Object find(String email) {',
      '    return session.createQuery("from User u where u.email = :email")',
      '        .setParameter("email", email)',
      '        .list();',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.hibernateSqlConcatenation,
      ),
    ).toHaveLength(0);
  });

  it('flags Runtime.getRuntime().exec with single string but not array form', () => {
    const text = [
      'class Cmd {',
      '  void run(String name) throws Exception {',
      '    Runtime.getRuntime().exec("ls -la " + name);',
      '    Runtime.getRuntime().exec(new String[]{"ls", "-la", name});',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.shellRuntimeExec,
      ),
    ).toHaveLength(1);
  });

  it('flags SecureRandom with literal byte array or short string seed', () => {
    const text = [
      'class R {',
      '  void make() {',
      '    SecureRandom a = new SecureRandom(new byte[]{1, 2, 3});',
      '    SecureRandom b = new SecureRandom("seed".getBytes());',
      '    SecureRandom c = new SecureRandom();',
      '    SecureRandom d = new SecureRandom(generateStrongSeed(32));',
      '  }',
      '}',
    ].join('\n');

    const facts = collectJavaAuditSecurityFacts({ text, path, detector });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_AUDIT_SECURITY_FACT_KINDS.predictableSecureRandom,
      ),
    ).toHaveLength(2);
  });
});
