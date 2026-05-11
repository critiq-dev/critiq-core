import { javaSourceAdapter } from './java';

describe('javaSourceAdapter', () => {
  it('analyzes valid Java source', () => {
    const result = javaSourceAdapter.analyze(
      'Main.java',
      [
        'class Main {',
        '  void run() {',
        '    System.out.println("ok");',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('java');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Java source', () => {
    const result = javaSourceAdapter.analyze(
      'Broken.java',
      [
        'class Broken {',
        '  void run( {',
        '    System.out.println("oops");',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = javaSourceAdapter.analyze(
      'Handler.java',
      [
        'class Handler {',
        '  void handle(HttpServletRequest request, Statement statement, Logger logger) throws Exception {',
        '    String apiSecret = "sk_live_12345678";',
        '    String reportName = request.getParameter("report");',
        '    Files.readString(reportName);',
        '    Runtime.getRuntime().exec(reportName);',
        '    String query = String.format("SELECT * FROM reports WHERE name = \'%s\'", reportName);',
        '    statement.executeQuery(query);',
        '    byte[] payload = request.getParameter("payload").getBytes();',
        '    ObjectInputStream stream = new ObjectInputStream(payload);',
        '    logger.info("token=" + request.getHeader("Authorization"));',
        '  }',
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
    const result = javaSourceAdapter.analyze(
      'Transport.java',
      [
        'class Transport {',
        '  void fetch() throws Exception {',
        '    HttpRequest.newBuilder(URI.create("http://api.example.com/users"));',
        '    HttpClient.newBuilder().hostnameVerifier((host, session) -> true).build();',
        '    MessageDigest.getInstance("MD5");',
        '  }',
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

  it('analyzes Spring YAML without Java delimiter validation', () => {
    const result = javaSourceAdapter.analyze(
      'src/main/resources/application.yml',
      [
        'management:',
        '  endpoints:',
        '    web:',
        '      exposure:',
        '        include: "*"',
        '  endpoint:',
        '    health:',
        '      show-details: always',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind) ?? [];
    expect(kinds).toContain('java.security.spring-actuator-sensitive-exposure');
    expect(kinds).toContain('java.security.spring-actuator-health-details-always');
  });

  it('emits Android client-safety facts', () => {
    const result = javaSourceAdapter.analyze(
      'LoginActivity.java',
      [
        'class LoginActivity extends AppCompatActivity {',
        '  void onCreate(Bundle savedInstanceState) {',
        '    String accessToken = loadToken();',
        '    openFileOutput("tokens.json", Context.MODE_WORLD_READABLE);',
        '    getSharedPreferences("prefs", MODE_WORLD_WRITEABLE);',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.android-screenshot-exposure',
      'security.android-world-readable-mode',
      'security.android-world-readable-mode',
    ]);
  });
});
