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
          }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            callee: 'webhook.send',
          }),
        }),
      ]),
    );
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
});

