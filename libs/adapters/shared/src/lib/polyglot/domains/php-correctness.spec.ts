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
});
