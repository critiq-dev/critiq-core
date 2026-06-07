import {
  collectPhpStructureCorrectnessFacts,
  PHP_STRUCTURE_CORRECTNESS_FACT_KINDS,
} from './php-structure-correctness';

describe('php-structure-correctness collectors', () => {
  it('flags PSR class constant naming violations', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: ['<?php', 'class Config {', '  const maxRetries = 3;', '}', ''].join(
        '\n',
      ),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.psrClassConstantNaming,
    );
  });

  it('flags trait class constants', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: ['<?php', 'trait Shared {', '  const VERSION = 1;', '}', ''].join(
        '\n',
      ),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.traitClassConstant,
    );
  });

  it('flags abstract methods with bodies', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'abstract class Base {',
        '  abstract function run() { return 1; }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.abstractMethodWithBody,
    );
  });

  it('flags nullable mixed union types', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: '<?php function demo(): ?mixed { return null; }',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.nullableMixedType,
    );
  });

  it('flags instantiation of abstract classes', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'abstract class Worker {}',
        '$worker = new Worker();',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instantiateAbstractClass,
    );
  });

  it('flags invalid isset arguments', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: '<?php isset($a = 1);',
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidIssetArgument,
    );
  });

  it('flags unused import statements', () => {
    const text = "<?php\nuse App\\UnusedType;\n";
    const pattern =
      /(?:^|\n)\s*use\s+([A-Za-z_\\][\w\\.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/gu;
    const matches = [...text.matchAll(pattern)];

    expect(matches).toHaveLength(1);

    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text,
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.unusedImport,
      ),
    ).toHaveLength(1);
  });

  it('flags attributes on named functions', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: "<?php\n#[Deprecated]\nfunction run() {}\n",
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnFunction,
    );
  });

  it('does not flag camelCase-only methods in clean PHP samples', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'function buildSettings(): array { return []; }',
        'final class WidgetFactory {',
        '  public function __construct(private readonly string $label) {}',
        '  public function make(): self { return $this; }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.psrMethodCamelCase,
      ),
    ).toHaveLength(0);
  });

  it('flags redundant final methods in final classes', () => {
    const facts = collectPhpStructureCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'final class Locked {',
        '  final function run() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.redundantFinalMethod,
    );
  });
});
