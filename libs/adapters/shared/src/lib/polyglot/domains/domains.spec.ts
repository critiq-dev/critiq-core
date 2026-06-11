import {
  collectHardcodedCredentialFacts,
  collectJavaInsecureCookieFacts,
  collectJavaOpenRedirectFacts,
  collectJavaQualityMaintainabilityFacts,
  collectJavaResponseWriterXssFacts,
  collectJavaSensitiveDataEgressFacts,
  collectJavaTestingHygieneFacts,
  collectSensitiveLoggingFacts,
  collectAndroidScreenshotExposureFacts,
  collectAndroidWorldReadableModeFacts,
  collectSpringConfigDebugExposureFacts,
  collectTlsVerificationDisabledFacts,
  type TrackedIdentifierState,
} from '../../shared';

describe('shared domain collectors', () => {
  it('flags only credential-like hardcoded assignments', () => {
    const facts = collectHardcodedCredentialFacts({
      detector: 'test-detector',
      text: [
        'const displayName = "Jane Smith";',
        'const apiSecret = "sk_live_12345678";',
      ].join('\n'),
      assignmentPattern:
        /(?:^|\n)\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'][^"'\n]{8,}["']/g,
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
    ]);
    expect(facts[0]?.text).toContain('apiSecret');
  });

  it('flags tainted logging and ignores redacted calls', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(['token']),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectSensitiveLoggingFacts({
      detector: 'test-detector',
      text: [
        'logger.info(token)',
        'logger.info(redact(token))',
      ].join('\n'),
      pattern: /\blogger\.info\s*\(/g,
      state,
      matchesTainted: (text, candidateState) =>
        candidateState.taintedIdentifiers.has('token') && text.includes('token'),
    });

    expect(facts).toHaveLength(1);
    expect(facts[0]?.kind).toBe('security.sensitive-data-in-logs-and-telemetry');
    expect(facts[0]?.text).toBe('logger.info(token)');
  });

  it('collects both snippet and raw TLS verification findings', () => {
    const facts = collectTlsVerificationDisabledFacts({
      detector: 'test-detector',
      text: [
        'requests.get("https://api.example.com", verify=False)',
        'ssl._create_unverified_context()',
      ].join('\n'),
      state: {},
      snippetPatterns: [
        {
          pattern: /\brequests\.get\s*\(/g,
          predicate: (snippet) => snippet.text.includes('verify=False'),
        },
      ],
      rawPatterns: [{ pattern: /\bssl\._create_unverified_context\s*\(/g }],
    });

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.tls-verification-disabled',
      'security.tls-verification-disabled',
    ]);
  });

  it('flags Java redirects fed by request sources', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectJavaOpenRedirectFacts({
      detector: 'test-detector',
      text: 'response.sendRedirect(request.getParameter("next"));',
      state,
      matchesTainted: (text) => /\brequest\.getParameter/u.test(text),
    });

    expect(facts.map((fact) => fact.kind)).toEqual(['security.open-redirect']);
  });

  it('flags servlet cookies with risky defaults or explicit insecure flags', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectJavaInsecureCookieFacts({
      detector: 'test-detector',
      text: [
        'Cookie session = new Cookie("JSESSIONID", token);',
        'ResponseCookie.from("sid", value).httpOnly(false).build();',
      ].join('\n'),
      state,
      matchesTainted: (text) => /\btoken\b/u.test(text),
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.servlet-insecure-cookie',
      'security.servlet-insecure-cookie',
    ]);
  });

  it('flags RestTemplate calls that forward request-controlled payloads externally', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectJavaSensitiveDataEgressFacts({
      detector: 'test-detector',
      text: 'restTemplate.postForObject(uri, request.getParameter("body"), String.class);',
      state,
      matchesTainted: (text) => /\brequest\.getParameter/u.test(text),
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.sensitive-data-egress',
    ]);
  });

  it('flags servlet responses that write request parameters to the writer', () => {
    const facts = collectJavaResponseWriterXssFacts({
      detector: 'test-detector',
      text: 'response.getWriter().print(request.getParameter("q"));',
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.java-reflected-output-from-request',
    ]);
  });

  it('flags Android world-readable file modes', () => {
    const facts = collectAndroidWorldReadableModeFacts({
      detector: 'test-detector',
      text: 'openFileOutput("backup.bin", Context.MODE_WORLD_READABLE);',
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.android-world-readable-mode',
    ]);
  });

  it('flags sensitive Android activities missing FLAG_SECURE', () => {
    const facts = collectAndroidScreenshotExposureFacts({
      detector: 'test-detector',
      text: [
        'class LoginActivity extends AppCompatActivity {',
        '  void onCreate(Bundle savedInstanceState) {',
        '    String accessToken = loadToken();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.android-screenshot-exposure',
    ]);
  });

  it('flags risky Spring Boot configuration in properties files', () => {
    const facts = collectSpringConfigDebugExposureFacts({
      detector: 'test-detector',
      path: 'application.properties',
      text: ['debug=true', 'logging.level.root=DEBUG'].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.spring-debug-exposure',
      'security.spring-debug-exposure',
    ]);
  });

  describe('java quality facts', () => {
    it('flags C-style array declaration', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'int arr[] = new int[5];',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.c-style-array-declaration')).toHaveLength(1);
    });

    it('does not flag Java-style array declaration', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'int[] arr = new int[5];',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.c-style-array-declaration')).toHaveLength(0);
    });

    it('flags type name with lowercase start', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'class myClass {}',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.type-name-uppercase')).toHaveLength(1);
    });

    it('does not flag type name with uppercase start', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'class MyClass {}',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.type-name-uppercase')).toHaveLength(0);
    });

    it('flags multiple variables on same line', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'int a, b = 5;',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.multiple-variables-same-line')).toHaveLength(1);
    });

    it('does not flag for-loop initializer', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: 'for (int i = 0, j = 0; i < n; i++) {}',
      });

      expect(facts.filter((f) => f.kind === 'java.quality.multiple-variables-same-line')).toHaveLength(0);
    });

    it('returns empty for clean code', () => {
      const facts = collectJavaQualityMaintainabilityFacts({
        detector: 'test-detector',
        path: 'Main.java',
        text: ['int[] arr = new int[5];', 'class MyClass {}', 'int a;', 'int b = 5;'].join('\n'),
      });

      expect(facts.filter((f) => f.kind.startsWith('java.quality.'))).toHaveLength(0);
    });
  });

  describe('java testing hygiene facts', () => {
    it('flags wrong assertion order: assertEquals(variable, literal)', () => {
      const facts = collectJavaTestingHygieneFacts({
        detector: 'test-detector',
        path: 'src/test/java/BadTest.java',
        text: 'assertEquals(val, 10);',
      });

      expect(facts.filter((f) => f.kind === 'java.testing.wrong-assertion-argument-order')).toHaveLength(1);
    });

    it('does not flag correct assertion order: assertEquals(literal, variable)', () => {
      const facts = collectJavaTestingHygieneFacts({
        detector: 'test-detector',
        path: 'src/test/java/GoodTest.java',
        text: 'assertEquals(10, val);',
      });

      expect(facts.filter((f) => f.kind === 'java.testing.wrong-assertion-argument-order')).toHaveLength(0);
    });

    it('flags assertThat(literal)', () => {
      const facts = collectJavaTestingHygieneFacts({
        detector: 'test-detector',
        path: 'src/test/java/BadTest.java',
        text: 'assertThat(10).isEqualTo(val);',
      });

      expect(facts.filter((f) => f.kind === 'java.testing.wrong-assertion-argument-order')).toHaveLength(1);
    });

    it('does not flag assertThat(variable)', () => {
      const facts = collectJavaTestingHygieneFacts({
        detector: 'test-detector',
        path: 'src/test/java/GoodTest.java',
        text: 'assertThat(val).isEqualTo(10);',
      });

      expect(facts.filter((f) => f.kind === 'java.testing.wrong-assertion-argument-order')).toHaveLength(0);
    });

    it('returns empty for non-test paths', () => {
      const facts = collectJavaTestingHygieneFacts({
        detector: 'test-detector',
        path: 'src/main/java/App.java',
        text: 'assertEquals(val, 10);',
      });

      expect(facts.filter((f) => f.kind === 'java.testing.wrong-assertion-argument-order')).toHaveLength(0);
    });
  });
});
