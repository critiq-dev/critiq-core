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

  describe('instanceof-invalid-type', () => {
    it('flags instanceof self outside class scope', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof self;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('flags instanceof parent outside class scope', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof parent;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('allows instanceof self inside class method', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Container {',
          '  public function check($a): bool {',
          '    return $a instanceof self;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(0);
    });

    it('allows instanceof parent inside child class', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends Base {',
          '  public function check($a): bool {',
          '    return $a instanceof parent;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(0);
    });

    it('flags instanceof with true keyword', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof true;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('flags instanceof with string literal', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof "MyClass";\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('flags instanceof with numeric literal', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof 42;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('ignores instanceof with valid identifier', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof SomeClass;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(0);
    });

    it('ignores instanceof with dynamic variable', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof $className;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(0);
    });

    it('flags instanceof self inside function (no class)', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function check($a): bool {',
          '  return $a instanceof self;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('allows instanceof self inside anonymous class', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$obj = new class {',
          '  public function check($a): bool {',
          '    return $a instanceof self;',
          '  }',
          '};',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(0);
    });

    it('flags instanceof self inside closure inside function (no class)', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function run(): void {',
          '  $check = function($a): bool {',
          '    return $a instanceof self;',
          '  };',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('flags instanceof null keyword', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: '<?php\n$a instanceof null;\n',
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(1);
    });

    it('counts multiple instanceof issues in same file', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$a instanceof self;',
          '$b instanceof parent;',
          '$c instanceof true;',
          '$d instanceof SomeClass;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType,
        ),
      ).toHaveLength(3);
    });
  });

  describe('attribute-on-property', () => {
    it('flags attribute with TARGET_CLASS used on property', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute(Attribute::TARGET_CLASS)]',
          'class ClassOnlyAttr {}',
          'class Foo {',
          '  #[ClassOnlyAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(1);
    });

    it('flags attribute with TARGET_METHOD used on property', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute(Attribute::TARGET_METHOD)]',
          'class MethodOnlyAttr {}',
          'class Foo {',
          '  #[MethodOnlyAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(1);
    });

    it('ignores attribute with TARGET_PROPERTY used on property', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute(Attribute::TARGET_PROPERTY)]',
          'class PropertyAttr {}',
          'class Foo {',
          '  #[PropertyAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores attribute with TARGET_ALL (no args) used on property', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute]',
          'class AllTargetsAttr {}',
          'class Foo {',
          '  #[AllTargetsAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores attribute class not defined in same file', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  #[UnknownAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores attribute on method (not a property)', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute(Attribute::TARGET_CLASS)]',
          'class ClassOnlyAttr {}',
          'class Foo {',
          '  #[ClassOnlyAttr]',
          '  public function run(): void {}',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores attribute with no target args (defaults to TARGET_ALL in PHP)', () => {
      const facts = collectPhpStructureCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '#[Attribute]',
          'class NoTargetAttr {}',
          'class Foo {',
          '  #[NoTargetAttr]',
          '  public string $prop;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty,
        ),
      ).toHaveLength(0);
    });
  });
});
