import { parse } from '@typescript-eslint/typescript-estree';

import { collectSensitiveEgressFacts } from './sensitive-egress';
import { type TypeScriptFactDetectorContext } from './shared';

function parseSource(sourceText: string) {
  return parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });
}

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/example.ts',
    program: parseSource(sourceText),
    sourceText,
  };
}

describe('collectSensitiveEgressFacts', () => {
  it('flags sensitive payloads sent to external processors', () => {
    const context = createContext([
      'const user = {',
      '  email: "ada@example.com",',
      '  phone: "+27 555 0100",',
      '};',
      '',
      'await fetch("https://api.example.com/ingest", {',
      '  method: "POST",',
      '  body: JSON.stringify({',
      '    email: user.email,',
      '    phone: user.phone,',
      '  }),',
      '});',
    ].join('\n'));

    expect(collectSensitiveEgressFacts(context)).toEqual([
      expect.objectContaining({
        kind: 'security.sensitive-data-egress',
        appliesTo: 'block',
        props: expect.objectContaining({
          callee: 'fetch',
          processorCategory: 'external-api',
          processorId: 'external-http-endpoint',
          sinkKind: 'http',
          datatypes: expect.arrayContaining(['email', 'phone']),
          sensitiveSignals: expect.arrayContaining(['email', 'phone']),
        }),
      }),
    ]);
  });

  it('flags analytics and webhook SDK calls that carry sensitive fields', () => {
    const context = createContext([
      'const payload = {',
      '  address: "1 Main St",',
      '  dob: "1980-01-01",',
      '};',
      '',
      'analytics.track("signup", { email: payload.address, dob: payload.dob });',
      'webhook.send({ token: user.token, email: user.email });',
    ].join('\n'));

    expect(collectSensitiveEgressFacts(context)).toHaveLength(2);
    expect(collectSensitiveEgressFacts(context)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'analytics.track',
            processorId: 'generic-analytics',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'webhook.send',
            processorId: 'webhook',
          }),
        }),
      ]),
    );
  });

  it('flags Google Tag Manager payloads that carry sensitive fields', () => {
    const context = createContext([
      'const user = { email: "ada@example.com", token: "abc" };',
      'window.dataLayer.push({ email: user.email, token: user.token });',
    ].join('\n'));

    expect(collectSensitiveEgressFacts(context)).toEqual([
      expect.objectContaining({
        kind: 'security.sensitive-data-egress',
        props: expect.objectContaining({
          callee: 'window.dataLayer.push',
          processorId: 'google_tag_manager',
          sensitiveSignals: expect.arrayContaining(['email', 'token']),
        }),
      }),
    ]);
  });

  it('flags the expanded vendor recipe set and emits normalized metadata', () => {
    const context = createContext([
      'const user = { email: "ada@example.com", token: "abc" };',
      'gtag("event", "signup", { email: user.email });',
      'DD_RUM.setUser({ email: user.email });',
      'segment.track("signup", { email: user.email });',
      'Sentry.setUser({ email: user.email });',
      'Rollbar.error("oops", { email: user.email });',
      'newrelic.setCustomAttribute("email", user.email);',
      'otel.setAttribute("token", user.token);',
      'algolia.search({ email: user.email });',
      'elasticsearch.index({ token: user.token });',
      'Bugsnag.notify(new Error("oops"), { email: user.email });',
      'Airbrake.notify({ email: user.email });',
      'Honeybadger.setContext({ token: user.token });',
      'openai.responses.create({ input: user.email });',
    ].join('\n'));

    const facts = collectSensitiveEgressFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'gtag',
            processorId: 'google_analytics',
            processorCategory: 'analytics',
            sinkKind: 'sdk',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'DD_RUM.setUser',
            processorId: 'datadog_browser',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'segment.track',
            processorId: 'segment',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'Sentry.setUser',
            processorId: 'sentry',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'Rollbar.error',
            processorId: 'rollbar',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'newrelic.setCustomAttribute',
            processorId: 'new_relic',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'otel.setAttribute',
            processorId: 'open_telemetry',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'algolia.search',
            processorId: 'algolia',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'elasticsearch.index',
            processorId: 'elasticsearch',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'Bugsnag.notify',
            processorId: 'bugsnag',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'Airbrake.notify',
            processorId: 'airbrake',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'Honeybadger.setContext',
            processorId: 'honeybadger',
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'openai.responses.create',
            processorId: 'openai',
            processorCategory: 'llm',
          }),
        }),
      ]),
    );
    expect(facts).toHaveLength(13);
  });

  it('ignores safe redaction wrappers and local endpoints', () => {
    const context = createContext([
      'const user = { email: "ada@example.com" };',
      '',
      'await fetch("http://localhost:3000/ingest", {',
      '  method: "POST",',
      '  body: JSON.stringify(redact(user)),',
      '});',
      '',
      'posthog.capture("signup", redactSensitiveData(user));',
    ].join('\n'));

    expect(collectSensitiveEgressFacts(context)).toEqual([]);
  });

  it('normalizes duplicate datatypes and skips unsupported instance-like sinks', () => {
    const context = createContext([
      'const user = { email: "ada@example.com", token: "abc" };',
      'fetch("https://api.example.com/ingest", {',
      '  method: "POST",',
      '  body: JSON.stringify({',
      '    email: user.email,',
      '    backupEmail: user.email,',
      '    token: user.token,',
      '  }),',
      '});',
      'client.index({ email: user.email });',
    ].join('\n'));

    expect(collectSensitiveEgressFacts(context)).toEqual([
      expect.objectContaining({
        props: expect.objectContaining({
          callee: 'fetch',
          datatypes: ['email', 'token'],
          sensitiveSignals: ['email', 'token'],
        }),
      }),
    ]);
  });
});
