import {
  collectAndroidScreenshotExposureFacts,
  collectAndroidWorldReadableModeFacts,
  collectHardcodedCredentialFacts,
  collectSensitiveLoggingFacts,
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

  it('flags Android activities that omit or clear FLAG_SECURE on sensitive screens', () => {
    const facts = collectAndroidScreenshotExposureFacts({
      detector: 'test-detector',
      text: [
        'class LoginActivity extends AppCompatActivity {',
        '  void onCreate(Bundle savedInstanceState) {',
        '    String accessToken = loadToken();',
        '  }',
        '}',
        'class WalletActivity extends Activity {',
        '  void onResume() {',
        '    getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.android-screenshot-exposure',
      'security.android-screenshot-exposure',
    ]);
    expect(facts.map((fact) => fact.props['reason'])).toEqual([
      'flag-secure-cleared',
      'flag-secure-cleared',
    ]);
  });

  it('flags Android world-readable or writable context modes', () => {
    const facts = collectAndroidWorldReadableModeFacts({
      detector: 'test-detector',
      text: [
        'openFileOutput("tokens.json", Context.MODE_WORLD_READABLE);',
        'getSharedPreferences("prefs", MODE_WORLD_WRITEABLE);',
      ].join('\n'),
    });

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.android-world-readable-mode',
      'security.android-world-readable-mode',
    ]);
  });
});
