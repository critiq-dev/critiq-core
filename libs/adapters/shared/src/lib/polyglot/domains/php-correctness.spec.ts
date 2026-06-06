import {
  collectPhpCorrectnessFacts,
  PHP_CORRECTNESS_FACT_KINDS,
} from './php-correctness';

describe('php-correctness collectors', () => {
  it('flags duplicate keys in array literals', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        '$settings = [',
        "  'mode' => 'safe',",
        "  'mode' => 'fast',",
        '];',
        '$legacy = array(',
        "  'id' => 1,",
        "  'id' => 2,",
        ');',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.duplicateArrayKey,
      ),
    ).toHaveLength(2);
  });

  it('flags switch statements with multiple default cases', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'switch ($value) {',
        '  case 1:',
        '    break;',
        '  default:',
        '    break;',
        '  default:',
        '    break;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.switchMultipleDefault,
    );
  });

  it('flags error suppression with @', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        '$value = @file_get_contents($path);',
        '@unlink($path);',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.errorSuppressionOperator,
      ).length,
    ).toBeGreaterThanOrEqual(2);
  });

  it('flags unreachable statements after return or throw', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'function done(): void {',
        '  return;',
        '  echo "never";',
        '}',
        'function fail(): void {',
        '  throw new RuntimeException("stop");',
        '  cleanup();',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.unreachableAfterReturn,
      ),
    ).toHaveLength(2);
  });

  it('flags nullsafe operators in by-reference arrow functions', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        '$getter = fn &() => $object?->property;',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.nullsafeReturnedByReference,
    );
  });

  it('does not flag safe patterns', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        '$settings = [',
        "  'mode' => 'safe',",
        "  'level' => 1,",
        '];',
        'switch ($value) {',
        '  case 1:',
        '    break;',
        '  default:',
        '    break;',
        '}',
        'if ($ready) {',
        '  return 1;',
        '}',
        'function load(): array {',
        '  return [',
        "    'mode' => 'safe',",
        '  ];',
        '}',
        'echo "still reachable";',
        '$value = file_get_contents($path);',
        '$getter = fn () => $object?->property;',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('flags empty array literal slots', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$items = [1, , 3];',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.emptyArrayLiteralSlot,
    );
  });

  it('flags empty bracket array reads', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$value = $items[];',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.emptyBracketArrayAccess,
    );
  });

  it('flags deprecated unset cast', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$value = (unset) $input;',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.deprecatedUnsetCast,
    );
  });

  it('flags duplicate top-level declarations', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        'function run() {}',
        'function run() {}',
        'class Worker {}',
        'class Worker {}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.duplicateDeclaration,
      ),
    ).toHaveLength(2);
  });

  it('flags nested function declarations', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        'function outer() {',
        '  function inner() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.nestedFunctionDeclaration,
    );
  });

  it('flags break and continue outside loops', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        'continue;',
        'break;',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.breakContinueOutsideLoop,
      ),
    ).toHaveLength(2);
  });

  it('flags abstract methods in concrete classes', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'class Worker { abstract function run(); }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.abstractMethodOutsideAbstractClass,
    );
  });

  it('flags useless unset calls', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'unset($this->value);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.uselessUnset,
    );
  });

  it('flags invalid preg regex literals', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: "preg_match('/(/', $input);",
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
    );
  });

  it('flags todo and fixme markers', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '// TODO: fix this',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.todoFixmeMarker,
    );
  });

  it('flags self assignment', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$value = $value;',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.selfAssignment,
    );
  });

  it('flags default parameters before required parameters', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'function run($limit = 10, $name) {}',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.defaultParameterNotLast,
    );
  });

  it('flags empty function bodies', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'function noop() {}',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.emptyFunctionBody,
    );
  });

  it('flags unknown magic methods', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'function __notReal() {}',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.unknownMagicMethod,
    );
  });

  it('flags case-insensitive define calls', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: "define('NAME', 'value', true);",
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.caseInsensitiveDefine,
    );
  });

  it('flags deprecated filter constants', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'filter_var($input, FILTER_SANITIZE_STRING);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.deprecatedFilterConstant,
    );
  });

  it('flags empty code blocks', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'if ($ready) {}',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.emptyCodeBlock,
    );
  });

  it('flags redundant string casts in concatenation', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$message = (string)$value . " suffix";',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.redundantStringCastConcat,
    );
  });

  it('flags missing member visibility', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: 'class Worker { function run() {} }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.missingMemberVisibility,
    );
  });

  it('flags callable array comparisons', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: "[$this, 'a'] <= [$this, 'b'];",
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.functionComparison,
    );
  });

  it('flags useless post increment statements', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: '$count++;',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.uselessPostIncrement,
    );
  });

  it('flags nested switch statements', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        'switch ($outer) {',
        '  case 1:',
        '    switch ($inner) {',
        '      case 2:',
        '        break;',
        '    }',
        '    break;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.nestedSwitch,
    );
  });

  it('flags invalid cookie option keys', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: "setcookie('session', 'abc', ['bad_option' => true]);",
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.invalidCookieOptions,
    );
  });
});
