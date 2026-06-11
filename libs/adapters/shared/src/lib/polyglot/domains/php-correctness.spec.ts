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
        '$getId = fn($item) => $item->id;',
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

  it('flags functions with return type but no return statement', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'function getName(): string {',
        '  $name = "hello";',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.missingReturnStatement,
    );
  });

  it('does not flag function with return type and return statement', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'function getName(): string {',
        '  return "hello";',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.missingReturnStatement,
      ),
    ).toHaveLength(0);
  });

  it('does not flag void functions without return', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'function log(string $msg): void {',
        '  echo $msg;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.missingReturnStatement,
      ),
    ).toHaveLength(0);
  });

  it('flags typed properties without defaults and no constructor assignment', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class User {',
        '  public string $name;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.uninitializedTypedProperty,
    );
  });

  it('does not flag typed property with constructor assignment', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class User {',
        '  public string $name;',
        '  public function __construct(string $name) {',
        '    $this->name = $name;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.uninitializedTypedProperty,
      ),
    ).toHaveLength(0);
  });

  it('does not flag typed property with default value', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class Config {',
        "  public string $mode = 'safe';",
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.uninitializedTypedProperty,
      ),
    ).toHaveLength(0);
  });

  it('flags throw with non-exception class', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'throw new stdClass();',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.throwNonException,
    );
  });

  it('does not flag throw with exception class', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'throw new \\RuntimeException("fail");',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.throwNonException,
      ),
    ).toHaveLength(0);
  });

  it('does not flag throw with Error class', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'throw new \\TypeError("bad");',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.throwNonException,
      ),
    ).toHaveLength(0);
  });

  it('flags unused constructor parameters', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class Service {',
        '  public function __construct($db, $cache) {',
        '    $this->db = $db;',
        '  }',
        '}',
      ].join('\n'),
    });

    const cacheFacts = facts.filter(
      (fact) =>
        fact.kind === PHP_CORRECTNESS_FACT_KINDS.unusedConstructorParameter &&
        fact.text === '$cache',
    );
    expect(cacheFacts).toHaveLength(1);
  });

  it('does not flag used constructor parameters', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class Service {',
        '  public function __construct($db, $cache) {',
        '    $this->db = $db;',
        '    $this->cache = $cache;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.unusedConstructorParameter,
      ),
    ).toHaveLength(0);
  });

  it('does not flag promoted constructor properties', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'class User {',
        '  public function __construct(',
        '    private string $name,',
        '    protected int $age',
        '  ) {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.unusedConstructorParameter,
      ),
    ).toHaveLength(0);
  });

  it('flags echo with object instantiation', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo new stdClass();',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.echoInvalidValue,
    );
  });

  it('flags echo with array literal', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo [1, 2, 3];',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.echoInvalidValue,
    );
  });

  it('flags echo with array() call', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo array(1, 2);',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.echoInvalidValue,
    );
  });

  it('does not flag echo with string', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo "hello world";',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.echoInvalidValue,
      ),
    ).toHaveLength(0);
  });

  it('flags print with object instantiation', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'print new DateTime();',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.printInvalidValue,
    );
  });

  it('flags print with array literal', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'print [1, 2];',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.printInvalidValue,
    );
  });

  it('does not flag print with string', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'print "hello";',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.printInvalidValue,
      ),
    ).toHaveLength(0);
  });

  it('flags invalid string interpolation with array literal', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo "value: ${[1,2,3]}";',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.invalidStringInterpolationType,
    );
  });

  it('flags invalid string interpolation with new expression', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        'echo "object: ${new stdClass()}";',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PHP_CORRECTNESS_FACT_KINDS.invalidStringInterpolationType,
    );
  });

  it('does not flag simple variable interpolation', () => {
    const facts = collectPhpCorrectnessFacts({
      detector: 'php-detector',
      text: [
        '<?php',
        '$name = "world";',
        'echo "hello $name";',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidStringInterpolationType,
      ),
    ).toHaveLength(0);
  });

  describe('undefined-function', () => {
    it('flags call to undefined function', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'processData($input);',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedFunction,
        ),
      ).toHaveLength(1);
    });

    it('does not flag defined-in-file function', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function processData($input) {',
          '  return $input;',
          '}',
          'processData($input);',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedFunction,
        ),
      ).toHaveLength(0);
    });

    it('does not flag built-in PHP function calls', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$result = array_merge($a, $b);',
          '$len = strlen($name);',
          '$items = explode(",", $csv);',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedFunction,
        ),
      ).toHaveLength(0);
    });

    it('does not flag method calls as function calls', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$obj->process($input);',
          '$this->handle($event);',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedFunction,
        ),
      ).toHaveLength(0);
    });

    it('does not flag function keyword definition', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function render() {}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedFunction,
        ),
      ).toHaveLength(0);
    });
  });

  describe('undefined-method', () => {
    it('flags $this->undefinedMethod() call', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function run(): void {',
          '    $this->undefinedCall();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(1);
    });

    it('does not flag defined method call', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function run(): void {',
          '    $this->run();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(0);
    });

    it('flags self::undefinedMethod() call', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function run(): void {',
          '    self::missing();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(1);
    });

    it('does not flag self::definedMethod() call', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function run(): void {',
          '    self::run();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(0);
    });

    it('does not flag magic method calls', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Magic {',
          '  public function __call($name, $args) {}',
          '  public function run(): void {',
          '    $this->__call("test", []);',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(0);
    });

    it('skips classes with extends keyword', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends Base {',
          '  public function run(): void {',
          '    $this->missing();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedMethod,
        ),
      ).toHaveLength(0);
    });
  });

  describe('invalid-static-method', () => {
    it('flags self::instanceMethod() when method is not static', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function process(): void {',
          '    self::process();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidStaticMethod,
        ),
      ).toHaveLength(1);
    });

    it('does not flag self::staticMethod() when method is static', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public static function process(): void {',
          '    self::process();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidStaticMethod,
        ),
      ).toHaveLength(0);
    });

    it('does not flag self::undefinedMethod() (undefined, not invalid static)', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Worker {',
          '  public function process(): void {',
          '    self::missing();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidStaticMethod,
        ),
      ).toHaveLength(0);
    });

    it('skips parent:: calls', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends Base {',
          '  public function process(): void {',
          '    parent::init();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidStaticMethod,
        ),
      ).toHaveLength(0);
    });
  });

  describe('invalid-attribute-class', () => {
    it('flags #[Attribute] on abstract class', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '#[Attribute]',
          'abstract class Validator {',
          '  public function validate(): bool { return true; }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
      );
    });

    it('flags #[Attribute] on interface', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '#[Attribute]',
          'interface FilterInterface {}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
      );
    });

    it('flags #[Attribute] class with private constructor', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '#[Attribute]',
          'class MyAttribute {',
          '  private function __construct() {}',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
      );
    });

    it('flags #[Attribute] class with protected constructor', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '#[Attribute]',
          'class MyAttribute {',
          '  protected function __construct() {}',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
      );
    });

    it('does not flag #[Attribute] class with public constructor', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '#[Attribute]',
          'class MyAttribute {',
          '  public function __construct() {}',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
        ),
      ).toHaveLength(0);
    });

    it('does not flag normal class without #[Attribute]', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class NormalClass {',
          '  public function __construct() {}',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidAttributeClass,
        ),
      ).toHaveLength(0);
    });
  });

  describe('invalid-use-keyword', () => {
    it('flags use inside interface', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'interface Loggable {',
          '  use LoggableTrait;',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword,
      );
    });

    it('flags use inside anonymous class', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$obj = new class {',
          '  use SomeTrait;',
          '};',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword,
      );
    });

    it('flags use of same-file class as trait', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Helper {',
          '  public function help(): void {}',
          '}',
          'class Consumer {',
          '  use Helper;',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword,
      );
    });

    it('does not flag valid trait use in class', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'trait LoggableTrait {',
          '  public function log(string $msg): void { echo $msg; }',
          '}',
          'class Consumer {',
          '  use LoggableTrait;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword,
        ),
      ).toHaveLength(0);
    });

    it('does not flag use at file top-level (namespace import)', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'use Some\\Namespace\\ClassName;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.invalidUseKeyword,
        ),
      ).toHaveLength(0);
    });
  });

  describe('inconsistent-printf-params', () => {
    it('flags sprintf with too many arguments', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('Hello %s', $name, $extra);",
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
      );
    });

    it('flags sprintf with too few arguments', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('Hello %s and %s', $name);",
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
      );
    });

    it('does not flag correct sprintf call', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('Hello %s', $name);",
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
        ),
      ).toHaveLength(0);
    });

    it('does not flag sprintf with no placeholders and no args', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('Hello world');",
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
        ),
      ).toHaveLength(0);
    });

    it('flags sprintf with no placeholders but arguments present', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('Hello world', $extra);",
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
      );
    });

    it('handles positional placeholders correctly', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sprintf('%1$s %1$s', $name);",
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
        ),
      ).toHaveLength(0);
    });

    it('flags sscanf with mismatched variable references', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          "sscanf($input, '%d %s', $id);",
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
      );
    });

    it('handles multi-line sprintf calls', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'sprintf(',
          "  'Count: %d',",
          '  $count,',
          '  $extra,',
          ');',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.inconsistentPrintfParams,
      );
    });
  });

  describe('undefined-property', () => {
    it('flags $this->undefinedProp access', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public string $name;',
          '  public function test(): void {',
          '    echo $this->undefinedProp;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(facts.map((fact) => fact.kind)).toContain(
        PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
      );
    });

    it('does not flag $this->definedProp access', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public string $name;',
          '  public function test(): void {',
          '    echo $this->name;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
        ),
      ).toHaveLength(0);
    });

    it('skips classes with extends', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends Base {',
          '  public function test(): void {',
          '    echo $this->undefinedProp;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
        ),
      ).toHaveLength(0);
    });

    it('skips classes with __get magic method', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Dynamic {',
          '  public function __get($name) { return $this->data[$name]; }',
          '  public function test(): void {',
          '    echo $this->anything;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
        ),
      ).toHaveLength(0);
    });

    it('recognizes constructor-promoted properties', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public function __construct(private string $name) {}',
          '  public function test(): void {',
          '    echo $this->name;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
        ),
      ).toHaveLength(0);
    });

    it('handles multiple classes in same file', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class First {',
          '  public string $a;',
          '  public function test(): void {',
          '    echo $this->missing;',
          '  }',
          '}',
          'class Second {',
          '  public string $b;',
          '  public function test(): void {',
          '    echo $this->b;',
          '  }',
          '}',
        ].join('\n'),
      });

      const undefFacts = facts.filter(
        (fact) => fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedProperty,
      );
      expect(undefFacts).toHaveLength(1);
    });
  });

  describe('undefined-static-property', () => {
    it('flags ClassName::$undefinedProp when property is not declared', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public static string $definedProp = "ok";',
          '}',
          '$val = Foo::$undefinedProp;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(1);
    });

    it('flags self::$missing inside a class lacking that static property', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Bar {',
          '  public static string $declared = "ok";',
          '  public function test(): void {',
          '    echo self::$missing;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(1);
    });

    it('ignores Foo::$definedProp where the property is declared static', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public static string $definedProp = "ok";',
          '}',
          '$val = Foo::$definedProp;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores $someVar::$prop (dynamic class reference)', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public static string $prop = "ok";',
          '}',
          '$className = "Foo";',
          '$val = $className::$prop;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(0);
    });

    it('ignores parent::$prop (cannot resolve parent class)', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends Base {',
          '  public function test(): void {',
          '    echo parent::$prop;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(0);
    });

    it('handles multiple classes in same file', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class First {',
          '  public static string $a = "ok";',
          '}',
          'class Second {',
          '  public static string $b = "ok";',
          '}',
          '$val = First::$missing;',
          '$val2 = Second::$b;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedStaticProperty,
        ),
      ).toHaveLength(1);
    });
  });

  describe('undefined-variable', () => {
    it('flags use-before-define in function scope', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo(): void {',
          '  echo $x;',
          '  $x = 5;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(1);
    });

    it('does not flag define-before-use', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo(): void {',
          '  $x = 5;',
          '  echo $x;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('flags $this in static method', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public static function bar(): void {',
          '    echo $this->prop;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(1);
    });

    it('does not flag $this in instance method', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Foo {',
          '  public function bar(): void {',
          '    echo $this->prop;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('flags post-unset variable use', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo(): void {',
          '  $y = 1;',
          '  unset($y);',
          '  echo $y;',
          '}',
        ].join('\n'),
      });

      const undefFacts = facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
      );
      expect(undefFacts.length).toBeGreaterThanOrEqual(1);
    });

    it('recognizes foreach binding as definition', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo(array $arr): void {',
          '  foreach ($arr as $val) {',
          '    echo $val;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('recognizes function parameter as definition', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo($x): void {',
          '  echo $x;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('recognizes catch binding as definition', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'function foo(): void {',
          '  try {',
          '    risky();',
          '  } catch (\\Exception $e) {',
          '    echo $e->getMessage();',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('recognizes global declaration as definition', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$x = 1;',
          'function foo(): void {',
          '  global $x;',
          '  echo $x;',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('ignores $$var variable variables', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$name = "hello";',
          'echo $$name;',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });

    it('handles arrow function parameters', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          '$fn = fn($x) => $x + 1;',
          'echo $fn(5);',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.undefinedVariable,
        ),
      ).toHaveLength(0);
    });
  });

  describe('inaccessible-property', () => {
    it('flags private parent property accessed from child', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class ParentClass {',
          '  private $secret;',
          '}',
          'class Child extends ParentClass {',
          '  public function foo(): void {',
          '    echo $this->secret;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty,
        ),
      ).toHaveLength(1);
    });

    it('does not flag public parent property from child', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class ParentClass {',
          '  public $name;',
          '}',
          'class Child extends ParentClass {',
          '  public function foo(): void {',
          '    echo $this->name;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty,
        ),
      ).toHaveLength(0);
    });

    it('skips classes with __get magic method', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Dynamic {',
          '  public function __get($name) { return $this->data[$name]; }',
          '  public function test(): void {',
          '    echo $this->anything;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty,
        ),
      ).toHaveLength(0);
    });

    it('skips cross-file parent class (extends with no same-file parent)', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Child extends ExternalBase {',
          '  public function test(): void {',
          '    echo $this->something;',
          '  }',
          '}',
        ].join('\n'),
      });

      expect(
        facts.filter(
          (fact) =>
            fact.kind === PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty,
        ),
      ).toHaveLength(0);
    });

    it('does not duplicate undefined-property findings', () => {
      const facts = collectPhpCorrectnessFacts({
        detector: 'php-detector',
        text: [
          '<?php',
          'class Simple {',
          '  public function test(): void {',
          '    echo $this->missing;',
          '  }',
          '}',
        ].join('\n'),
      });

      const inaccessibleFacts = facts.filter(
        (fact) =>
          fact.kind === PHP_CORRECTNESS_FACT_KINDS.inaccessibleProperty,
      );
      expect(inaccessibleFacts).toHaveLength(0);
    });
  });
});
