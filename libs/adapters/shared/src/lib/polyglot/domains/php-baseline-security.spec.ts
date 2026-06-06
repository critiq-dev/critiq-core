import type { TrackedIdentifierState } from '../types';

import {
  collectPhpBaselineSecurityFacts,
  PHP_BASELINE_SECURITY_FACT_KINDS,
} from './php-baseline-security';

function matchesTainted(
  expression: string,
  state: TrackedIdentifierState,
): boolean {
  return (
    /\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/u.test(expression) ||
    [...state.taintedIdentifiers].some((identifier) =>
      new RegExp(`\\$${identifier}\\b`, 'u').test(expression),
    )
  );
}

describe('php baseline security collectors', () => {
  const emptyState: TrackedIdentifierState = {
    taintedIdentifiers: new Set(),
    sqlInterpolatedIdentifiers: new Set(),
  };

  const baseOptions = {
    path: 'src/Handler.php',
    detector: 'php-detector',
    state: emptyState,
    matchesTainted,
  };

  it('flags eval, create_function, and string assert', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: [
        'eval($_POST["code"]);',
        'create_function("", $body);',
        'assert("$x == 1");',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.noDynamicEval,
      ),
    ).toHaveLength(3);
  });

  it('does not flag boolean assert', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: 'assert($value > 0);',
    });

    expect(
      facts.some(
        (fact) => fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.noDynamicEval,
      ),
    ).toBe(false);
  });

  it('flags include with request-tainted path', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: 'include $_GET["page"] . ".php";',
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind ===
          PHP_BASELINE_SECURITY_FACT_KINDS.unsafeIncludeWithUserInput,
      ),
    ).toBe(true);
  });

  it('flags include with propagated taint', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(['template']),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      state,
      text: 'require_once $template;',
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind ===
          PHP_BASELINE_SECURITY_FACT_KINDS.unsafeIncludeWithUserInput,
      ),
    ).toBe(true);
  });

  it('flags weak openssl cipher and mcrypt usage', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: [
        'openssl_encrypt($data, "DES-ECB", $key);',
        'mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.weakCipher,
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it('flags insecure session_id generation patterns', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: [
        'session_id(md5(uniqid()));',
        'session_id($_POST["sid"]);',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind ===
          PHP_BASELINE_SECURITY_FACT_KINDS.insecureSessionIdGeneration,
      ).length,
    ).toBe(2);
  });

  it('flags xml loads without entity hardening', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: '$doc = new DOMDocument(); $doc->loadXML($xml);',
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.xmlExternalEntity,
      ),
    ).toBe(true);
  });

  it('suppresses xml loads when entity loader is disabled', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: [
        'libxml_disable_entity_loader(true);',
        '$doc = new DOMDocument();',
        '$doc->loadXML($xml, LIBXML_NONET);',
      ].join('\n'),
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.xmlExternalEntity,
      ),
    ).toBe(false);
  });

  it('flags debug helpers outside test paths', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      path: 'src/Debug.php',
      text: 'var_dump($user);',
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.debugFunctionExposure,
      ),
    ).toBe(true);
  });

  it('suppresses debug helpers in test paths', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      path: 'tests/Handler_test.php',
      text: 'var_dump($fixture);',
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.debugFunctionExposure,
      ),
    ).toBe(false);
  });

  it('flags new static in non-final classes', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: 'class Worker { public function build() { return new static(); } }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_BASELINE_SECURITY_FACT_KINDS.unsafeNewStatic,
    );
  });

  it('does not flag new static in final classes', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: 'final class Worker { public function build() { return new static(); } }',
    });

    expect(
      facts.some(
        (fact) => fact.kind === PHP_BASELINE_SECURITY_FACT_KINDS.unsafeNewStatic,
      ),
    ).toBe(false);
  });

  it('flags deprecated libxml_disable_entity_loader usage', () => {
    const facts = collectPhpBaselineSecurityFacts({
      ...baseOptions,
      text: 'libxml_disable_entity_loader(true);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_BASELINE_SECURITY_FACT_KINDS.deprecatedLibxmlEntityLoader,
    );
  });
});
