import { parse } from '@typescript-eslint/typescript-estree';

import { collectSensitiveLoggingFacts } from './sensitive-logging';
import type { TypeScriptFactDetectorContext } from './shared';

function buildContext(sourceText: string): TypeScriptFactDetectorContext {
  const program = parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/example.ts',
    program,
    sourceText,
  };
}

describe('collectSensitiveLoggingFacts', () => {
  it('flags sensitive data reaching logging and telemetry sinks', () => {
    const sourceText = [
      'declare const logger: {',
      '  warn(value: unknown): void;',
      '  info(value: unknown): void;',
      '};',
      '',
      'declare const analytics: {',
      '  track(event: string, payload: unknown): void;',
      '};',
      '',
      'declare const user: {',
      '  email: string;',
      '};',
      '',
      'declare const session: {',
      '  token: string;',
      '};',
      '',
      'declare function redact<T>(value: T): T;',
      '',
      'logger.warn({ email: user.email });',
      'analytics.track("signup", { token: session.token });',
      'logger.info(redact({ email: user.email }));',
    ].join('\n');

    const facts = collectSensitiveLoggingFacts(buildContext(sourceText));

    expect(facts).toHaveLength(2);
    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.sensitive-data-in-logs-and-telemetry',
          appliesTo: 'function',
          props: expect.objectContaining({
            sink: 'logger.warn',
            datatype: 'email',
          }),
        }),
        expect.objectContaining({
          kind: 'security.sensitive-data-in-logs-and-telemetry',
          appliesTo: 'function',
          props: expect.objectContaining({
            sink: 'analytics.track',
            datatype: 'token',
          }),
        }),
      ]),
    );
  });

  it('does not flag redacted sensitive values', () => {
    const sourceText = [
      'declare const logger: {',
      '  info(value: unknown): void;',
      '};',
      '',
      'declare const user: {',
      '  email: string;',
      '};',
      '',
      'declare function redact<T>(value: T): T;',
      '',
      'logger.info(redact({ email: user.email }));',
    ].join('\n');

    const facts = collectSensitiveLoggingFacts(buildContext(sourceText));

    expect(facts).toHaveLength(0);
  });

  it('does not treat non-sensitive event name strings as disclosed data', () => {
    const sourceText = [
      'declare const analytics: {',
      '  track(event: string, payload: unknown): void;',
      '};',
      '',
      'analytics.track("user-profile", {',
      '  userId: "customer-123",',
      '  channel: "web",',
      '});',
    ].join('\n');

    const facts = collectSensitiveLoggingFacts(buildContext(sourceText));

    expect(facts).toHaveLength(0);
  });
});
