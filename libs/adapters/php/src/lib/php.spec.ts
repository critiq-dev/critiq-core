import { phpSourceAdapter } from './php';

describe('phpSourceAdapter', () => {
  it('analyzes valid PHP source', () => {
    const result = phpSourceAdapter.analyze(
      'app.php',
      [
        '<?php',
        'function run() {',
        '  echo "ok";',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('php');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed PHP source', () => {
    const result = phpSourceAdapter.analyze(
      'broken.php',
      [
        '<?php',
        'function run() {',
        '  echo("oops";',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = phpSourceAdapter.analyze(
      'service.php',
      [
        '<?php',
        '$apiSecret = "sk_live_12345678";',
        '$reportName = $_GET["report"];',
        'error_log("token=" . $_SERVER["HTTP_AUTHORIZATION"]);',
        'readfile($reportName);',
        'exec($reportName);',
        '$query = "SELECT * FROM reports WHERE name = \'" . $reportName . "\'";',
        '$pdo->query($query);',
        '$payload = $_POST["payload"];',
        'unserialize($payload);',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind),
    ).toEqual(
      expect.arrayContaining([
        'security.hardcoded-credentials',
        'security.sensitive-data-in-logs-and-telemetry',
        'security.request-path-file-read',
        'security.command-execution-with-request-input',
        'security.sql-interpolation',
        'security.unsafe-deserialization',
      ]),
    );
  });

  it('emits transport and crypto security facts', () => {
    const result = phpSourceAdapter.analyze(
      'transport.php',
      [
        '<?php',
        'file_get_contents("http://api.example.com/users");',
        'curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);',
        'sha1("payload");',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind),
    ).toEqual(
      expect.arrayContaining([
        'security.insecure-http-transport',
        'security.tls-verification-disabled',
        'security.weak-hash-algorithm',
      ]),
    );
  });

  it('emits php framework and wordpress facts', () => {
    const result = phpSourceAdapter.analyze(
      'framework.php',
      [
        '<?php',
        '$user->update($request->all());',
        "protected $except = ['account/*'];",
        '$builder->setMethod("POST");',
        '$builder->setAttribute("csrf_protection", false);',
        'add_action("wp_ajax_delete_invoice", function () {',
        '  delete_invoice($_POST["invoice_id"]);',
        '});',
        '$wpdb->query("DELETE FROM wp_meta WHERE id = " . $_GET["id"]);',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map(
      (fact) => fact.kind,
    );
    expect(kinds).toEqual(
      expect.arrayContaining([
        'php.security.laravel-unsafe-mass-assignment',
        'php.security.laravel-sensitive-csrf-exclusion',
        'php.security.symfony-csrf-disabled',
        'php.security.wordpress-missing-nonce-or-capability',
        'php.security.wordpress-unprepared-sql',
      ]),
    );
  });
});
