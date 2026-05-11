import {
  collectJavaFrameworkSecurityFacts,
  isJavaFrameworkSuppressedPath,
  JAVA_FRAMEWORK_SECURITY_FACT_KINDS,
} from './java-framework-security';

describe('isJavaFrameworkSuppressedPath', () => {
  it('suppresses test and generated paths', () => {
    expect(isJavaFrameworkSuppressedPath('src/test/java/demo/FooTest.java')).toBe(true);
    expect(isJavaFrameworkSuppressedPath('src/main/java/demo/Foo.java')).toBe(false);
  });
});

describe('collectJavaFrameworkSecurityFacts', () => {
  const detector = 'java-detector';

  it('flags anyRequest permitAll chains', () => {
    const text = [
      '@Bean',
      'SecurityFilterChain web(HttpSecurity http) throws Exception {',
      '  return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();',
      '}',
    ].join('\n');

    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/java/demo/SecurityConfig.java',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springPermitAllDefault,
    );
  });

  it('flags CSRF disable without stateless hardening hints', () => {
    const text = [
      'return http.csrf(csrf -> csrf.disable())',
      '  .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());',
    ].join('\n');

    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/java/demo/SecurityConfig.java',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springCsrfGloballyDisabled,
    );
  });

  it('skips CSRF disable when OAuth2 resource server is configured', () => {
    const text = [
      'return http.csrf(csrf -> csrf.disable())',
      '  .oauth2ResourceServer(oauth2 -> oauth2.jwt())',
      '  .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());',
    ].join('\n');

    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/java/demo/SecurityConfig.java',
      detector,
    });

    expect(facts.map((f) => f.kind)).not.toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springCsrfGloballyDisabled,
    );
  });

  it('flags actuator exposure in properties', () => {
    const text = 'management.endpoints.web.exposure.include=env,beans\n';
    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/resources/application.properties',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springActuatorSensitiveExposure,
    );
  });

  it('flags actuator include star in YAML', () => {
    const text = [
      'management:',
      '  endpoints:',
      '    web:',
      '      exposure:',
      '        include: "*"',
    ].join('\n');

    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/resources/application.yml',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springActuatorSensitiveExposure,
    );
  });

  it('flags health show-details always in properties', () => {
    const text = 'management.endpoint.health.show-details=always\n';
    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/resources/application.properties',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springActuatorHealthDetailsAlways,
    );
  });

  it('flags JPA createQuery with string concatenation', () => {
    const text =
      'return em.createQuery("select u from User u where u.email = \'" + request.getParameter("email") + "\'").getResultList();';

    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/java/demo/UserRepo.java',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.jpaConcatenatedQuery,
    );
  });

  it('flags Thymeleaf th utext with param', () => {
    const text = '<div th:utext="${param.preview}"></div>';
    const facts = collectJavaFrameworkSecurityFacts({
      text,
      path: 'src/main/resources/templates/x.html',
      detector,
    });

    expect(facts.map((f) => f.kind)).toContain(
      JAVA_FRAMEWORK_SECURITY_FACT_KINDS.templateUnescapedUserOutput,
    );
  });
});
