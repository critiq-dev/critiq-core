import {
  collectJavaCorrectnessFacts,
  JAVA_CORRECTNESS_FACT_KINDS,
} from './java-correctness';

describe('java-correctness collectors', () => {
  it('flags empty catch blocks', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    try {',
        '      doWork();',
        '    } catch (Exception e) {',
        '      // ignored',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.emptyCatch,
    );
  });

  it('flags catching NullPointerException', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    try {',
        '      doWork();',
        '    } catch (NullPointerException npe) {',
        '      log(npe);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.catchNullPointer,
    );
  });

  it('flags equals on array variables', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(String[] left, String[] right) {',
        '    return left.equals(right);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.equalsOnArray),
    ).toHaveLength(1);
  });

  it('flags synchronized blocks on string literals', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    synchronized("lock") {',
        '      doWork();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncOnStringLiteral,
    );
  });

  it('flags Optional.get() without a nearby guard', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String resolve(Optional<String> value) {',
        '    log("resolving");',
        '    log("starting");',
        '    log("about to call");',
        '    log("here we go");',
        '    return value.get();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsafeOptionalGet,
      ),
    ).toHaveLength(1);
  });

  it('does not flag Optional.get() when a guard is nearby', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String resolve(Optional<String> value) {',
        '    if (value.isPresent()) {',
        '      return value.get();',
        '    }',
        '    return "";',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsafeOptionalGet,
      ),
    ).toHaveLength(0);
  });

  it('flags return inside finally block', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int run() {',
        '    try {',
        '      return doWork();',
        '    } finally {',
        '      return -1;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.returnInFinally,
    );
  });

  it('does not flag control-flow inside nested lambdas in finally blocks', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run(java.util.List<String> items) {',
        '    try {',
        '      doWork();',
        '    } finally {',
        '      items.forEach(item -> {',
        '        if (item.isEmpty()) {',
        '          return;',
        '        }',
        '      });',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.returnInFinally,
      ),
    ).toHaveLength(0);
  });

  it('does not flag safe Java patterns', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Arrays;',
        'class Demo {',
        '  boolean compare(String[] left, String[] right) {',
        '    return Arrays.equals(left, right);',
        '  }',
        '  void run(Object lock) {',
        '    synchronized (lock) {',
        '      doWork();',
        '    }',
        '    try {',
        '      doWork();',
        '    } catch (IllegalArgumentException e) {',
        '      log(e);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
