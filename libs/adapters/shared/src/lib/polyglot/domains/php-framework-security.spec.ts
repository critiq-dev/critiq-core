import type { TrackedIdentifierState } from '../types';

import {
  collectPhpFrameworkSecurityFacts,
  collectPhpSensitiveDataEgressFacts,
} from './php-framework-security';

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

describe('php framework security collectors', () => {
  const emptyState: TrackedIdentifierState = {
    taintedIdentifiers: new Set(),
    sqlInterpolatedIdentifiers: new Set(),
  };

  it('flags laravel mass assignment from request all', () => {
    const facts = collectPhpFrameworkSecurityFacts({
      text: '$user->update($request->all());',
      path: 'app/Http/Controllers/UserController.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });

    expect(
      facts.some(
        (fact) => fact.kind === 'php.security.laravel-unsafe-mass-assignment',
      ),
    ).toBe(true);
  });

  it('flags sensitive csrf wildcard exclusions and suppresses signed webhook', () => {
    const invalid = collectPhpFrameworkSecurityFacts({
      text: "protected $except = ['account/*', 'billing/*'];",
      path: 'app/Http/Middleware/VerifyCsrfToken.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });
    const valid = collectPhpFrameworkSecurityFacts({
      text: "protected $except = ['webhooks/stripe/*'];",
      path: 'app/Http/Middleware/VerifyCsrfToken.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });

    expect(
      invalid.some(
        (fact) => fact.kind === 'php.security.laravel-sensitive-csrf-exclusion',
      ),
    ).toBe(true);
    expect(
      valid.some(
        (fact) => fact.kind === 'php.security.laravel-sensitive-csrf-exclusion',
      ),
    ).toBe(false);
  });

  it('flags symfony csrf disabled for state changes', () => {
    const facts = collectPhpFrameworkSecurityFacts({
      text: [
        '$builder->setMethod("POST");',
        '$builder->setAttribute("csrf_protection", false);',
      ].join('\n'),
      path: 'src/Form/SettingsType.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });

    expect(
      facts.some((fact) => fact.kind === 'php.security.symfony-csrf-disabled'),
    ).toBe(true);
  });

  it('flags wordpress ajax callback missing nonce and capability', () => {
    const facts = collectPhpFrameworkSecurityFacts({
      text: [
        'add_action("wp_ajax_delete_invoice", function () {',
        '  delete_invoice($_POST["invoice_id"]);',
        '});',
      ].join('\n'),
      path: 'wp-content/plugins/invoice/admin.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === 'php.security.wordpress-missing-nonce-or-capability',
      ),
    ).toBe(true);
  });

  it('suppresses wordpress callback with nonce and capability checks', () => {
    const facts = collectPhpFrameworkSecurityFacts({
      text: [
        'add_action("wp_ajax_delete_invoice", function () {',
        '  check_ajax_referer("delete_invoice");',
        '  if (!current_user_can("manage_options")) { return; }',
        '  delete_invoice($_POST["invoice_id"]);',
        '});',
      ].join('\n'),
      path: 'wp-content/plugins/invoice/admin.php',
      detector: 'php-detector',
      state: emptyState,
      matchesTainted,
    });

    expect(
      facts.some(
        (fact) =>
          fact.kind === 'php.security.wordpress-missing-nonce-or-capability',
      ),
    ).toBe(false);
  });

  it('flags sensitive data egress from outbound requests', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(['payload']),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectPhpSensitiveDataEgressFacts({
      text: 'curl_exec($payload);',
      detector: 'php-detector',
      state,
      matchesTainted,
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.sensitive-data-egress',
    ]);
  });
});
