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

  it('flags synchronized on getClass()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    synchronized (getClass()) {',
        '      doWork();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncOnGetClass,
    );
  });

  it('flags StringBuilder/StringBuffer constructor with char literal', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  StringBuilder sb = new StringBuilder(\'a\');',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.stringBuilderCharCtor,
    );
  });

  it('flags public static date format fields', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public static SimpleDateFormat sdf = new SimpleDateFormat("yyyy");',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.staticDateField,
    );
  });

  it('flags array index out of bounds patterns', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run(int[] arr) {',
        '    int x = arr[arr.length];',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.arrayIndexBounds,
    );
  });

  it('flags charAt with length()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  char last(String s) {',
        '    return s.charAt(s.length());',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.arrayIndexBounds,
    );
  });

  it('flags list.get(list.size()) as out of bounds', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'class Demo {',
        '  Object last(List<String> items) {',
        '    return items.get(items.size());',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.arrayIndexBounds,
    );
  });

  it('flags stream reuse on the same variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.stream.Stream;',
        'class Demo {',
        '  long run(Stream<String> stream) {',
        '    long c = stream.count();',
        '    return stream.count();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.streamReuse,
    );
  });

  it('flags Optional variable assigned null', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Optional;',
        'class Demo {',
        '  void run() {',
        '    Optional<String> opt = null;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.optionalNull,
    );
  });

  it('flags return null in Optional-returning method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Optional;',
        'class Demo {',
        '  Optional<String> findName() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.optionalNull,
    );
  });

  it('flags unconditional recursion', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int factorial(int n) {',
        '    return factorial(n - 1);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unconditionalRecursion,
    );
  });

  it('flags double-checked locking without volatile', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private Object instance;',
        '  Object getInstance() {',
        '    if (instance == null) {',
        '      synchronized (this) {',
        '        if (instance == null) {',
        '          instance = new Object();',
        '        }',
        '      }',
        '    }',
        '    return instance;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.doubleCheckedLocking,
    );
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

  it('flags Pattern.compile with unescaped whitespace escape', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    Pattern.compile("\\n[error]");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unescapedWhitespace,
    );
  });

  it('does not flag Pattern.compile with properly escaped regex', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    Pattern.compile("\\\\n[error]");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unescapedWhitespace,
      ),
    ).toHaveLength(0);
  });

  it('flags import of sun.* internal APIs', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import sun.misc.BASE64Encoder;',
        'class Demo {}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unsupportedJdkApi,
    );
  });

  it('does not flag java.util.Base64 import', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Base64;',
        'class Demo {}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsupportedJdkApi,
      ),
    ).toHaveLength(0);
  });

  it('flags Double.NaN comparison using ==', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(double x) {',
        '    return x == Double.NaN;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.nanComparison,
    );
  });

  it('does not flag Double.isNaN()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(double x) {',
        '    return Double.isNaN(x);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.nanComparison,
      ),
    ).toHaveLength(0);
  });

  it('flags readResolve with wrong return type', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String readResolve() { return "x"; }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.readResolveReturnType,
    );
  });

  it('does not flag readResolve with Object return type', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Object readResolve() { return this; }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.readResolveReturnType,
      ),
    ).toHaveLength(0);
  });

  it('flags serialization method with wrong access modifier', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public void writeObject(java.io.ObjectOutputStream out) {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.serializationMethodSignature,
    );
  });

  it('does not flag correct serialization method signature', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private void writeObject(java.io.ObjectOutputStream out) throws IOException {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.serializationMethodSignature,
      ),
    ).toHaveLength(0);
  });

  it('flags class extending non-serializable superclass while implementing Serializable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class NonSerializableParent {',
        '  NonSerializableParent(int x) {}',
        '}',
        'class Child extends NonSerializableParent implements Serializable {',
        '  private static final long serialVersionUID = 1L;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.serializableSuperclass,
    );
  });

  it('flags Collection.remove with numeric argument on likely string-typed collection', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'class Demo {',
        '  void run(List<String> stringList) {',
        '    stringList.remove(42);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.collectionRemoveTypeMismatch,
    );
  });

  it('does not flag Collection.remove with matching type', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'class Demo {',
        '  void run(List<String> stringList) {',
        '    stringList.remove("hello");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.collectionRemoveTypeMismatch,
      ),
    ).toHaveLength(0);
  });

  it('flags unsafe collection downcast without instanceof guard', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'import java.util.LinkedList;',
        'class Demo {',
        '  void run(List<String> names) {',
        '    LinkedList<String> q = (LinkedList<String>) names;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unsafeCollectionDowncast,
    );
  });

  it('does not flag collection downcast with instanceof guard', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'import java.util.LinkedList;',
        'class Demo {',
        '  void run(List<String> names) {',
        '    if (names instanceof LinkedList) {',
        '      LinkedList<String> q = (LinkedList<String>) names;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsafeCollectionDowncast,
      ),
    ).toHaveLength(0);
  });

  it('flags annotation check with SOURCE retention', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.lang.annotation.Retention;',
        'import java.lang.annotation.RetentionPolicy;',
        '@Retention(RetentionPolicy.SOURCE)',
        '@interface Marker {}',
        'class Demo {',
        '  boolean check() {',
        '    return getClass().isAnnotationPresent("Marker");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.annotationCheckAlwaysFalse,
    );
  });

  it('does not flag annotation check with RUNTIME retention', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.lang.annotation.Retention;',
        'import java.lang.annotation.RetentionPolicy;',
        '@Retention(RetentionPolicy.RUNTIME)',
        '@interface Marker {}',
        'class Demo {',
        '  boolean check() {',
        '    return getClass().isAnnotationPresent("Marker");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.annotationCheckAlwaysFalse,
      ),
    ).toHaveLength(0);
  });

  it('flags interface method clashing with Object final methods', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'interface Bad {',
        '  int toString();',
        '  void wait();',
        '}',
      ].join('\n'),
    });

    const filtered = facts.filter(
      (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unimplementableInterface,
    );
    expect(filtered).toHaveLength(2);
  });

  it('does not flag interface without clashing methods', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'interface Good {',
        '  String getName();',
        '  void doSomething();',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unimplementableInterface,
      ),
    ).toHaveLength(0);
  });

  it('flags invalid serialVersionUID without static final long', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public static int serialVersionUID = 3;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.invalidSerialVersionUid,
    );
  });

  it('does not flag properly declared serialVersionUID', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public static final long serialVersionUID = 3L;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.invalidSerialVersionUid,
      ),
    ).toHaveLength(0);
  });

  it('flags hashCode() call on array variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int run(String[] arr) {',
        '    return arr.hashCode();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.hashCodeOnArray,
    );
  });

  it('does not flag Arrays.hashCode as hashCode on array', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Arrays;',
        'class Demo {',
        '  int run(String[] arr) {',
        '    return Arrays.hashCode(arr);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.hashCodeOnArray,
      ),
    ).toHaveLength(0);
  });

  it('flags while(false) loop condition', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    while (false) { doWork(); }',
        '  }',
        '  void doWork() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.loopConditionNeverTrue,
    );
  });

  it('does not flag while with variable condition', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run(int count) {',
        '    while (count > 0) { count--; }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.loopConditionNeverTrue,
      ),
    ).toHaveLength(0);
  });

  it('flags non-terminating while(true) loop', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    while (true) { doWork(); }',
        '  }',
        '  void doWork() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.nonTerminatingLoop,
    );
  });

  it('does not flag while(true) with break', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run(boolean done) {',
        '    while (true) { if (done) break; doWork(); }',
        '  }',
        '  void doWork() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.nonTerminatingLoop,
      ),
    ).toHaveLength(0);
  });

  it('flags call to final method that throws UnsupportedOperationException', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  final void bad() { throw new UnsupportedOperationException(); }',
        '  void caller() { bad(); }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unsupportedMethodCall,
    );
  });

  it('does not flag non-final method with UnsupportedOperationException', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void bad() { throw new UnsupportedOperationException(); }',
        '  void caller() { bad(); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsupportedMethodCall,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: sync-on-mutable-ref ---

  it('flags synchronized on non-final instance field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private Object lock = new Object();',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncOnMutableRef,
    );
  });

  it('does not flag synchronized on final field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private final Object lock = new Object();',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.syncOnMutableRef,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: unsync-static-lazy-init ---

  it('flags unsynchronized static lazy initialization', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private static Foo instance;',
        '  static Foo getInstance() {',
        '    if (instance == null) {',
        '      instance = new Foo();',
        '    }',
        '    return instance;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unsyncStaticLazyInit,
    );
  });

  it('does not flag synchronized static lazy initialization', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private static Foo instance;',
        '  static synchronized Foo getInstance() {',
        '    if (instance == null) {',
        '      instance = new Foo();',
        '    }',
        '    return instance;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsyncStaticLazyInit,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: boxed-boolean-conditional ---

  it('flags boxed Boolean used in if condition', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void check() {',
        '    Boolean flag = getFlag();',
        '    if (flag) {',
        '      work();',
        '    }',
        '  }',
        '  Boolean getFlag() { return true; }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.boxedBooleanConditional,
    );
  });

  it('does not flag guarded boxed Boolean', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void check() {',
        '    Boolean flag = getFlag();',
        '    if (flag != null && flag) {',
        '      work();',
        '    }',
        '  }',
        '  Boolean getFlag() { return true; }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.boxedBooleanConditional,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: sync-on-nullable-field ---

  it('flags synchronized on nullable field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private Object lock;',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncOnNullableField,
    );
  });

  it('does not flag synchronized on initialized field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private Object lock = new Object();',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.syncOnNullableField,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: sync-on-public-field ---

  it('flags synchronized on public field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public Object lock = new Object();',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncOnPublicField,
    );
  });

  it('does not flag synchronized on private final field', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private final Object lock = new Object();',
        '  void run() {',
        '    synchronized (lock) { work(); }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.syncOnPublicField,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: thread-static-misuse ---

  it('flags instance thread.sleep() misuse', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() throws Exception {',
        '    Thread t = new Thread();',
        '    t.sleep(100);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.threadStaticMisuse,
    );
  });

  it('does not flag Thread.sleep() correctly', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() throws Exception {',
        '    Thread.sleep(100);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.threadStaticMisuse,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 16: double-assignment ---

  it('flags double assignment without intervening read', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    int x = a();',
        '    x = b();',
        '  }',
        '  int a() { return 1; }',
        '  int b() { return 2; }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.doubleAssignment,
    );
  });

  it('does not flag assignment with intervening read', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    int x = a();',
        '    foo(x);',
        '    x = b();',
        '  }',
        '  int a() { return 1; }',
        '  int b() { return 2; }',
        '  void foo(int v) {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.doubleAssignment,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: invalid-time-constants ---

  it('flags LocalDate.of with month > 12', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.LocalDate;',
        'class Demo {',
        '  void run() {',
        '    LocalDate d = LocalDate.of(2024, 13, 1);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.invalidTimeConstants,
    );
  });

  it('does not flag LocalDate.of with valid month', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.LocalDate;',
        'class Demo {',
        '  void run() {',
        '    LocalDate d = LocalDate.of(2024, 6, 15);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.invalidTimeConstants,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: comparator-downcast-sign-flip ---

  it('flags (short)(a - b) in compare method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Comparator;',
        'class Demo implements Comparator<Integer> {',
        '  public int compare(Integer a, Integer b) {',
        '    return (short)(a - b);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.comparatorDowncastSignFlip,
    );
  });

  it('does not flag Long.compare usage', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Comparator;',
        'class Demo implements Comparator<Integer> {',
        '  public int compare(Integer a, Integer b) {',
        '    return Long.compare(a, b);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.comparatorDowncastSignFlip,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: cacheloader-null-return ---

  it('flags CacheLoader load() returning null', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import com.google.common.cache.CacheLoader;',
        'class MyLoader extends CacheLoader<String, String> {',
        '  public String load(String key) {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.cacheloaderNullReturn,
    );
  });

  it('does not flag load() returning non-null', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import com.google.common.cache.CacheLoader;',
        'class MyLoader extends CacheLoader<String, String> {',
        '  public String load(String key) {',
        '    return "cached:" + key;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.cacheloaderNullReturn,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: incorrect-main-signature ---

  it('flags main method without static', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public void main(String[] args) {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.incorrectMainSignature,
    );
  });

  it('does not flag correct main signature', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public static void main(String[] args) {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.incorrectMainSignature,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: enum-get-class ---

  it('flags getClass() in enum body', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Status {',
        '  ACTIVE;',
        '  Class<?> get() { return getClass(); }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.enumGetClass,
    );
  });

  it('does not flag getDeclaringClass() in enum body', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Status {',
        '  ACTIVE;',
        '  Class<?> get() { return getDeclaringClass(); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.enumGetClass,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 17: deprecated-thread-methods ---

  it('flags thread.stop() call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    Thread t = new Thread();',
        '    t.stop();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.deprecatedThreadMethods,
    );
  });

  it('does not flag Thread.sleep()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() throws Exception {',
        '    Thread.sleep(100);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.deprecatedThreadMethods,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 19 (JAVA-E) tests ─────────────────────────────

  it('flags possible null access on chained .get() call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String get(Map<String, String> m, String k) {',
        '    return m.get(k).toString();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.possibleNullAccess,
    );
  });

  it('flags invalidated iterator when collection modified in for-each loop', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'class Demo {',
        '  void run(List<String> items) {',
        '    for (String item : items) {',
        '      if (item.isEmpty()) {',
        '        items.remove(item);',
        '      }',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.invalidatedIterator,
    );
  });

  it('flags Duration.withNanos() call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.Duration;',
        'class Demo {',
        '  Duration adjust(Duration d) {',
        '    return d.withNanos(500_000_000);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.durationWithNanosMisuse,
    );
  });

  it('flags indexOf with reversed arguments', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int find(String text) {',
        '    return text.indexOf(0, "target");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.indexOfReversedArguments,
    );
  });

  it('flags Collections.nCopies with reversed arguments', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Collections;',
        'class Demo {',
        '  void run() {',
        '    Collections.nCopies("ten", 10);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.nCopiesArgumentOrder,
    );
  });

  it('flags class.isInstance() pattern', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(Object obj) {',
        '    return String.class.isInstance(obj);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.classIsInstanceOnClass,
    );
  });

  // ── Batch 15 (JAVA-E) tests ─────────────────────────────

  it('flags ZoneId.of() with hardcoded string', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.ZoneId;',
        'class Demo {',
        '  ZoneId get() { return ZoneId.of("invalid_tz"); }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.zoneIdInvalidTimezone,
    );
  });

  it('does not flag ZoneId.of() with no hardcoded string', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.ZoneId;',
        'class Demo {',
        '  ZoneId get(String tz) { return ZoneId.of(tz); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.zoneIdInvalidTimezone,
      ),
    ).toHaveLength(0);
  });

  it('flags TimeZone.getTimeZone() with hardcoded string', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.TimeZone;',
        'class Demo {',
        '  TimeZone get() { return TimeZone.getTimeZone("invalid_tz"); }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.timezoneInvalidId,
    );
  });

  it('does not flag TimeZone.getTimeZone() with variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.TimeZone;',
        'class Demo {',
        '  TimeZone get(String id) { return TimeZone.getTimeZone(id); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.timezoneInvalidId,
      ),
    ).toHaveLength(0);
  });

  it('flags Instant.plus() with unsupported ChronoUnit', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.Instant;',
        'import java.time.temporal.ChronoUnit;',
        'class Demo {',
        '  Instant get() { return Instant.now().plus(1, ChronoUnit.WEEKS); }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.instantUnsupportedTemporalUnit,
    );
  });

  it('does not flag Instant.plus() with DAYS', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.time.Instant;',
        'import java.time.temporal.ChronoUnit;',
        'class Demo {',
        '  Instant get() { return Instant.now().plus(1, ChronoUnit.DAYS); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.instantUnsupportedTemporalUnit,
      ),
    ).toHaveLength(0);
  });

  it('flags Iterable<Path> type usage', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.nio.file.Path;',
        'class Demo {',
        '  void process(Iterable<Path> paths) {}',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.iterablePathType,
    );
  });

  it('does not flag Collection<Path> type usage', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.nio.file.Path;',
        'import java.util.Collection;',
        'class Demo {',
        '  void process(Collection<Path> paths) {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.iterablePathType,
      ),
    ).toHaveLength(0);
  });

  it('flags throw null statement', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    if (true) throw null;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.throwNull,
    );
  });

  it('does not flag throw with exception instance', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    throw new RuntimeException();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.throwNull,
      ),
    ).toHaveLength(0);
  });

  it('does not flag return null', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Object get() { return null; }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.throwNull,
      ),
    ).toHaveLength(0);
  });

  it('flags Hashtable.contains() call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Hashtable;',
        'class Demo {',
        '  boolean check(Hashtable<String, String> t) {',
        '    return t.contains("key");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.hashtableContainsValue,
    );
  });

  it('does not flag List.contains() call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.List;',
        'class Demo {',
        '  boolean check(List<String> items) {',
        '    return items.contains("key");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.hashtableContainsValue,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 21 (JAVA-S) — system-exit ---

  it('flags System.exit() calls', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void shutdown() {',
        '    System.exit(1);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.systemExit,
    );
  });

  it('does not flag code without System.exit', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void shutdown() {',
        '    System.out.println("exiting");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.systemExit,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 22 (JAVA-E) — unterminated assertion chain ---

  it('flags bare assertThat() without chain', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void test() {',
        '    assertThat(value);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
    );
  });

  it('flags bare verify() without chain', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void test() {',
        '    verify(mockObj);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
    );
  });

  it('does not flag assertThat() with terminal assertion', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void test() {',
        '    assertThat(value).isGreaterThan(5);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
      ),
    ).toHaveLength(0);
  });

  it('does not flag verify() with chained method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void test() {',
        '    verify(mockObj).someMethod();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
      ),
    ).toHaveLength(0);
  });

  it('does not flag assertThat in variable assignment with chain', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void test() {',
        '    String x = assertThat(val).asString();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.unterminatedAssertChain,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 06 (JAVA-E) tests ─────────────────────────────

  it('flags volatile array declaration', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  volatile int[] counters;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.volatileArrayElements,
    );
  });

  it('does not flag volatile scalar declaration', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  volatile int x;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.volatileArrayElements,
      ),
    ).toHaveLength(0);
  });

  it('flags volatile increment as non-atomic', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  volatile int counter;',
        '  void inc() { counter++; }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.volatileIncrementNonAtomic,
    );
  });

  it('does not flag AtomicInteger as volatile increment', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  AtomicInteger ai = new AtomicInteger();',
        '  void inc() { ai.incrementAndGet(); }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.volatileIncrementNonAtomic,
      ),
    ).toHaveLength(0);
  });

  it('flags unsafe getResource relative path', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void load() {',
        '    getClass().getResource("config.xml");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.unsafeGetresource,
    );
  });

  it('does not flag getResource with absolute path', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void load() {',
        '    getClass().getResource("/config.xml");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.unsafeGetresource,
      ),
    ).toHaveLength(0);
  });

  it('flags duplicate binary argument', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void check(int x) {',
        '    if (x == 0 || x == 0) {}',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.duplicateBinaryArgument,
    );
  });

  it('does not flag distinct binary arguments', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void check(int x, int y) {',
        '    if (x == 0 || y == 0) {}',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.duplicateBinaryArgument,
      ),
    ).toHaveLength(0);
  });

  it('flags catching IllegalMonitorStateException', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    try {',
        '      doWork();',
        '    } catch (IllegalMonitorStateException e) {',
        '      log(e);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.illegalMonitorStateCaught,
    );
  });

  it('does not flag catching IOException', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    try {',
        '      doWork();',
        '    } catch (IOException e) {',
        '      log(e);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.illegalMonitorStateCaught,
      ),
    ).toHaveLength(0);
  });

  it('flags clone() without super.clone()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo implements Cloneable {',
        '  public Object clone() {',
        '    return new Demo();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.cloneWithoutSuper,
    );
  });

  it('does not flag clone() with super.clone()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo implements Cloneable {',
        '  public Object clone() throws CloneNotSupportedException {',
        '    return super.clone();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.cloneWithoutSuper,
      ),
    ).toHaveLength(0);
  });

  it('flags x.equals(null)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(String x) {',
        '    return x.equals(null);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.equalsNull,
    );
  });

  it('does not flag x.equals("hello")', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean check(String x) {',
        '    return x.equals("hello");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.equalsNull,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 07 (JAVA-E) tests ─────────────────────────────

  it('flags non-final field in @Immutable class', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        '@Immutable',
        'class Demo {',
        '  private String name;',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.nonFinalImmutableFields,
    );
  });

  it('does not flag final field in @Immutable class', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        '@Immutable',
        'class Demo {',
        '  private final String name;',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_CORRECTNESS_FACT_KINDS.nonFinalImmutableFields,
      ),
    ).toHaveLength(0);
  });

  it('flags unsafe runFinalizersOnExit call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    System.runFinalizersOnExit(true);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.runfinalizersOnExit,
    );
  });

  it('does not flag normal Runtime call', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    Runtime.getRuntime().exec("ls");',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_CORRECTNESS_FACT_KINDS.runfinalizersOnExit,
      ),
    ).toHaveLength(0);
  });

  it('flags wait() call on Condition variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    Condition c = lock.newCondition();',
        '    c.wait();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.waitOnCondition,
    );
  });

  it('does not flag Object.wait() on synchronized object', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    synchronized(obj) {',
        '      obj.wait();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.waitOnCondition,
      ),
    ).toHaveLength(0);
  });

  it('flags swapped Math.max/Math.min arguments', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    double x = Math.max(x, Math.min(x, y));',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.mathMaxMinSwapped,
    );
  });

  it('does not flag correct Math.max/Math.min usage', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void run() {',
        '    double r = Math.max(x, Math.min(y, z));',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_CORRECTNESS_FACT_KINDS.mathMaxMinSwapped,
      ),
    ).toHaveLength(0);
  });

  it('flags explicit finalize() invocation', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void clean() {',
        '    obj.finalize();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.explicitFinalizerInvocation,
    );
  });

  it('does not flag super.finalize() inside finalize method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  protected void finalize() throws Throwable {',
        '    super.finalize();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.explicitFinalizerInvocation,
      ),
    ).toHaveLength(0);
  });

  it('flags equals method defined in enum', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color {',
        '  RED, GREEN, BLUE;',
        '  public boolean equals(Object o) {',
        '    return super.equals(o);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.enumEqualsMethod,
    );
  });

  it('does not flag enum without equals method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color {',
        '  RED, GREEN, BLUE',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_CORRECTNESS_FACT_KINDS.enumEqualsMethod,
      ),
    ).toHaveLength(0);
  });

  it('flags overloaded equals with non-Object parameter', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public boolean equals(String s) {',
        '    return false;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.overloadedEquals,
    );
  });

  it('does not flag correctly overridden equals(Object)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  public boolean equals(Object obj) {',
        '    return false;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === JAVA_CORRECTNESS_FACT_KINDS.overloadedEquals,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 08 (JAVA-E) tests ─────────────────────────────

  it('flags equals inherits parent without Object override', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Parent {',
        '  public boolean equals(Object o) { return true; }',
        '}',
        'class Child extends Parent {',
        '  public boolean equals(Child c) { return true; }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.equalsInheritsParent,
    );
  });

  it('does not flag equals when Object override present', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Parent {',
        '  public boolean equals(Object o) { return true; }',
        '}',
        'class Child extends Parent {',
        '  public boolean equals(Child c) { return true; }',
        '  @Override',
        '  public boolean equals(Object o) { return true; }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.equalsInheritsParent,
      ),
    ).toHaveLength(0);
  });

  it('flags equals(Object) without null check and with dereference', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String name;',
        '  public boolean equals(Object o) {',
        '    String other = (String) o;',
        '    return this.name.equals(o.toString());',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.equalsNullCheck,
    );
  });

  it('does not flag equals with null guard', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String name;',
        '  public boolean equals(Object o) {',
        '    if (o == null) return false;',
        '    return this.name.equals(o.toString());',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.equalsNullCheck,
      ),
    ).toHaveLength(0);
  });

  it('flags compareTo returning Integer.MIN_VALUE', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo implements Comparable<Demo> {',
        '  public int compareTo(Demo other) {',
        '    return Integer.MIN_VALUE;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.comparetoMinValue,
    );
  });

  it('does not flag compareTo returning -1', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo implements Comparable<Demo> {',
        '  public int compareTo(Demo other) {',
        '    return -1;',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.comparetoMinValue,
      ),
    ).toHaveLength(0);
  });

  it('flags servlet mutable field access in doGet', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class MyServlet extends HttpServlet {',
        '  private String name;',
        '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) {',
        '    resp.getWriter().write(name);',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.servletMutableFields,
    );
  });

  it('does not flag servlet with synchronized access', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class MyServlet extends HttpServlet {',
        '  private String name;',
        '  protected void doGet(HttpServletRequest req, HttpServletResponse resp) {',
        '    synchronized (this) {',
        '      resp.getWriter().write(name);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.servletMutableFields,
      ),
    ).toHaveLength(0);
  });

  it('flags direct .run() call on thread variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void go() {',
        '    Thread t = new Thread(r);',
        '    t.run();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.runnableRunDirect,
    );
  });

  it('does not flag thread.start()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void go() {',
        '    Thread t = new Thread(r);',
        '    t.start();',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.runnableRunDirect,
      ),
    ).toHaveLength(0);
  });

  it('flags wait() inside nested synchronized blocks', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Object a = new Object();',
        '  Object b = new Object();',
        '  void go() throws InterruptedException {',
        '    synchronized (a) {',
        '      synchronized (b) {',
        '        b.wait();',
        '      }',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.twoLockWait,
    );
  });

  it('does not flag wait() inside single synchronized block', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Object a = new Object();',
        '  void go() throws InterruptedException {',
        '    synchronized (a) {',
        '      a.wait();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.twoLockWait,
      ),
    ).toHaveLength(0);
  });

  it('flags synchronized on boxed primitive variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Integer count = 0;',
        '  void go() {',
        '    synchronized (count) {',
        '      count++;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.syncBoxedPrimitive,
    );
  });

  it('does not flag synchronized on Object lock', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  Object lock = new Object();',
        '  void go() {',
        '    synchronized (lock) {',
        '      work();',
        '    }',
        '  }',
        '  void work() {}',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.syncBoxedPrimitive,
      ),
    ).toHaveLength(0);
  });

  it('flags class name collision with fully-qualified super type', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Foo extends com.other.Foo {',
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.classNameCollision,
    );
  });

  it('does not flag class with different super type name', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Foo extends com.other.Bar {',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === JAVA_CORRECTNESS_FACT_KINDS.classNameCollision,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 10 (JAVA-E) — bug risk / framework facts ---

  describe('collectResultSetIndexZeroFacts', () => {
    it('flags rs.getString(0)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void get() {',
          '    String s = rs.getString(0);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.resultSetIndexZero,
      );
    });

    it('flags resultSet.updateInt(0, 42)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void update() {',
          '    resultSet.updateInt(0, 42);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.resultSetIndexZero,
      );
    });

    it('does not flag rs.getString(1)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void get() {',
          '    String s = rs.getString(1);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.resultSetIndexZero,
        ),
      ).toHaveLength(0);
    });

    it('does not flag getXxx(0L) (long literal)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void get() {',
          '    String s = rs.getString(0L);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.resultSetIndexZero,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectPreparedStatementIndexZeroFacts', () => {
    it('flags pstmt.setString(0, "val")', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void set() throws Exception {',
          '    pstmt.setString(0, "val");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.preparedStatementIndexZero,
      );
    });

    it('flags preparedStatement.setNull(0, Types.VARCHAR)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void set() throws Exception {',
          '    preparedStatement.setNull(0, java.sql.Types.VARCHAR);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.preparedStatementIndexZero,
      );
    });

    it('does not flag pstmt.setString(1, "val")', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void set() throws Exception {',
          '    pstmt.setString(1, "val");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.preparedStatementIndexZero,
        ),
      ).toHaveLength(0);
    });

    it('does not flag statement.setFetchSize(0)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void set() throws Exception {',
          '    statement.setFetchSize(0);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.preparedStatementIndexZero,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectImpossibleToArrayDowncastFacts', () => {
    it('flags (String[]) list.toArray()', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void convert() {',
          '    String[] arr = (String[]) list.toArray();',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.impossibleToArrayDowncast,
      );
    });

    it('does not flag list.toArray(new String[0])', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'import java.util.List;',
          'class Test {',
          '  void convert() {',
          '    List<String> list = new ArrayList<>();',
          '    String[] arr = list.toArray(new String[0]);',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.impossibleToArrayDowncast,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectInvalidRegexLiteralFacts', () => {
    it('flags Pattern.compile("[z-a]") for reversed range', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    Pattern.compile("[z-a]");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
      );
    });

    it('flags Pattern.compile("[invalid") for unmatched bracket', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'import java.util.regex.Pattern;',
          'class Test {',
          '  void run() {',
          '    Pattern.compile("[invalid");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
      );
    });

    it('flags Pattern.compile("(unclosed") for unmatched paren', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    Pattern.compile("(unclosed");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
      );
    });

    it('does not flag Pattern.compile("[a-z]")', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    Pattern.compile("[a-z]");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
        ),
      ).toHaveLength(0);
    });

    it('does not flag Pattern.compile("\\\\d+")', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    Pattern.compile("\\\\d+");',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.invalidRegexLiteral,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectLostIncrementInAssignmentFacts', () => {
    it('flags x = x++', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    int x = 0;',
          '    x = x++;',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
      );
    });

    it('flags y = y--', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    int y = 0;',
          '    y = y--;',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(facts.map((f) => f.kind)).toContain(
        JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
      );
    });

    it('does not flag x = y++ (different variable)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    int x = 0;',
          '    int y = 0;',
          '    x = y++;',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag x = x + 1', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    int x = 0;',
          '    x = x + 1;',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag x++ alone', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    int x = 0;',
          '    x++;',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
        ),
      ).toHaveLength(0);
    });

    it('does not flag for (int i = 0; i < n; i++)', () => {
      const facts = collectJavaCorrectnessFacts({
        detector: 'java-detector',
        text: [
          'class Test {',
          '  void run() {',
          '    for (int i = 0; i < n; i++) {',
          '      System.out.println(i);',
          '    }',
          '  }',
          '}',
        ].join('\n'),
      });
      expect(
        facts.filter(
          (f) =>
            f.kind === JAVA_CORRECTNESS_FACT_KINDS.lostIncrementInAssignment,
        ),
      ).toHaveLength(0);
    });
  });
});

describe('collectShiftOutOfRangeFacts', () => {
  it('flags negative shift amount', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    int x = val << -1;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.shiftOutOfRange,
    );
  });

  it('flags shift amount >= 64', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    int x = val >> 64;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.shiftOutOfRange,
    );
  });

  it('does not flag valid shift << 4', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    int x = val << 4;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.shiftOutOfRange,
      ),
    ).toHaveLength(0);
  });

  it('does not flag long shift 1L << 48', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    long y = 1L << 48;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.shiftOutOfRange,
      ),
    ).toHaveLength(0);
  });
});

describe('collectOddnessCheckFailsNegativeFacts', () => {
  it('flags x % 2 == 1', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  boolean isOdd(int n) {',
        '    return n % 2 == 1;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.oddnessCheckFailsNegative,
    );
  });

  it('does not flag x % 2 != 0', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  boolean isOdd(int n) {',
        '    return n % 2 != 0;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.oddnessCheckFailsNegative,
      ),
    ).toHaveLength(0);
  });

  it('does not flag x % 2 == 0 (evenness check)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  boolean isEven(int n) {',
        '    return n % 2 == 0;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.oddnessCheckFailsNegative,
      ),
    ).toHaveLength(0);
  });
});

describe('collectHasNextInvokesNextFacts', () => {
  it('flags .next() call when hasNext method exists', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class MyIterator implements Iterator<String> {',
        '  public boolean hasNext() {',
        '    return iterator.next() != null;',
        '  }',
        '  public String next() {',
        '    return "x";',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.hasNextInvokesNext,
    );
  });

  it('does not flag when no hasNext method', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    list.next();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.hasNextInvokesNext,
      ),
    ).toHaveLength(0);
  });
});

describe('collectThreadSleepWithLockFacts', () => {
  it('flags Thread.sleep when synchronized present', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    synchronized (lock) {',
        '      Thread.sleep(100);',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.threadSleepWithLock,
    );
  });

  it('does not flag Thread.sleep without synchronized', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() throws Exception {',
        '    Thread.sleep(100);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.threadSleepWithLock,
      ),
    ).toHaveLength(0);
  });
});

describe('collectStringFormatArgMismatchFacts', () => {
  it('flags String.format with mismatched args', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    String.format("%s %d", name);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.stringFormatArgMismatch,
    );
  });

  it('does not flag String.format with matching args', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    String.format("%s %d", name, age);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.stringFormatArgMismatch,
      ),
    ).toHaveLength(0);
  });

  it('does not flag with escaped percent %%', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    String.format("%%s", name);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.stringFormatArgMismatch,
      ),
    ).toHaveLength(0);
  });
});

describe('collectBadShortCircuitNullCheckFacts', () => {
  it('flags x != null || x.foo()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(Object obj) {',
        '    if (obj != null || obj.toString().isEmpty()) {',
        '      System.out.println("bad");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.badShortCircuitNullCheck,
    );
  });

  it('flags x == null || x.foo()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(Object obj) {',
        '    if (obj == null || obj.isEmpty()) {',
        '      System.out.println("bad");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.badShortCircuitNullCheck,
    );
  });

  it('does not flag x != null && x.foo()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(Object obj) {',
        '    if (obj != null && obj.toString().isEmpty()) {',
        '      System.out.println("ok");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.badShortCircuitNullCheck,
      ),
    ).toHaveLength(0);
  });

  it('does not flag different variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(Object obj, String other) {',
        '    if (obj == null || other.isEmpty()) {',
        '      System.out.println("ok");',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.badShortCircuitNullCheck,
      ),
    ).toHaveLength(0);
  });
});

describe('collectWaitNotifyOnThreadFacts', () => {
  it('flags thread.wait() on thread-named variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    Thread worker = new Thread();',
        '    synchronized (worker) {',
        '      worker.wait();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.waitNotifyOnThread,
    );
  });

  it('flags Thread.currentThread().notify()', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    Thread.currentThread().notify();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.waitNotifyOnThread,
    );
  });

  it('does not flag lock.wait() on non-thread variable', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    Object lock = new Object();',
        '    synchronized (lock) {',
        '      lock.wait();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.waitNotifyOnThread,
      ),
    ).toHaveLength(0);
  });
});

describe('collectSwitchStatementLabelsFacts', () => {
  it('flags statement labels inside switch blocks', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(int val) {',
        '    switch (val) {',
        '      case 1:',
        '        break;',
        '      myLabel:',
        '        break;',
        '      default:',
        '        break;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.switchStatementLabels,
    );
  });

  it('does not flag switch with only case and default labels', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run(int val) {',
        '    switch (val) {',
        '      case 1:',
        '        break;',
        '      case 2:',
        '        break;',
        '      default:',
        '        break;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.switchStatementLabels,
      ),
    ).toHaveLength(0);
  });
});

describe('collectWeekYearInDatePatternFacts', () => {
  it('flags YYYY date pattern without week year usage', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    new SimpleDateFormat("YYYY-MM-dd");',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.weekYearInDatePattern,
    );
  });

  it('does not flag yyyy date pattern', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    new SimpleDateFormat("yyyy-MM-dd");',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.weekYearInDatePattern,
      ),
    ).toHaveLength(0);
  });
});

describe('collectJumpInFinallyFacts', () => {
  it('flags return inside finally block', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  int run() {',
        '    try {',
        '      return 1;',
        '    } finally {',
        '      return -1;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.jumpInFinally,
    );
  });

  it('does not flag finally block without return/throw', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  int run() {',
        '    try {',
        '      return 1;',
        '    } finally {',
        '      cleanup();',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.jumpInFinally,
      ),
    ).toHaveLength(0);
  });
});

describe('collectDefaultPackageSpringScanFacts', () => {
  it('flags @SpringBootApplication in default package', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import org.springframework.boot.SpringApplication;',
        'import org.springframework.boot.autoconfigure.SpringBootApplication;',
        '@SpringBootApplication',
        'public class App {',
        '  public static void main(String[] args) {',
        '    SpringApplication.run(App.class, args);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.defaultPackageSpringScan,
    );
  });

  it('does not flag @SpringBootApplication in named package', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'package com.example;',
        'import org.springframework.boot.SpringApplication;',
        'import org.springframework.boot.autoconfigure.SpringBootApplication;',
        '@SpringBootApplication',
        'public class App {',
        '  public static void main(String[] args) {',
        '    SpringApplication.run(App.class, args);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.defaultPackageSpringScan,
      ),
    ).toHaveLength(0);
  });
});

describe('collectCaseInsensitiveRegexLacksUnicodeFacts', () => {
  it('flags Pattern.compile with CASE_INSENSITIVE but no UNICODE_CASE', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    Pattern.compile("foo", Pattern.CASE_INSENSITIVE);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.caseInsensitiveRegexLacksUnicode,
    );
  });

  it('does not flag when both CASE_INSENSITIVE and UNICODE_CASE are present', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    Pattern.compile("foo", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.caseInsensitiveRegexLacksUnicode,
      ),
    ).toHaveLength(0);
  });
});

describe('collectAssertSelfComparisonFacts', () => {
  it('flags assertEquals with same object', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    assertEquals(expected, expected);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.assertSelfComparison,
    );
  });

  it('does not flag assertEquals with different objects', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  void run() {',
        '    assertEquals(expected, actual);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.assertSelfComparison,
      ),
    ).toHaveLength(0);
  });
});

describe('collectOptionalGetWithoutPresentCheckFacts', () => {
  it('flags Optional.get without isPresent check', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Optional;',
        'class Test {',
        '  String run(Optional<String> opt) {',
        '    return opt.get();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.optionalGetWithoutPresentCheck,
    );
  });
});

describe('collectIterableIteratorReturnsThisFacts', () => {
  it('flags iterator() returning this in class implementing both Iterable and Iterator', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test implements Iterable<String>, Iterator<String> {',
        '  public Iterator<String> iterator() {',
        '    return this;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.iterableIteratorReturnsThis,
    );
  });

  it('does not flag iterator() returning new iterator', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test implements Iterable<String> {',
        '  public Iterator<String> iterator() {',
        '    return new MyIterator();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.iterableIteratorReturnsThis,
      ),
    ).toHaveLength(0);
  });

  // ── Batch 13 (JAVA-E) tests ─────────────────────────────

  it('flags (int) Math.random() without scaling', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int rand() {',
        '    return (int) Math.random();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.randomCoercedToZero,
    );
  });

  it('does not flag (int) Math.random() with scaling factor', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int rand() {',
        '    return (int) (Math.random() * 100);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.randomCoercedToZero,
      ),
    ).toHaveLength(0);
  });

  it('flags new Random().nextInt(1)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'import java.util.Random;',
        'class Demo {',
        '  int rand() {',
        '    return new Random().nextInt(1);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.randomCoercedToZero,
    );
  });

  it('flags non-final fields in enum body', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color {',
        '  RED, GREEN, BLUE;',
        '  private String label;',
        '  private final String name;',
        '  String getLabel() { return label; }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.mutableEnumFields,
    );
  });

  it('does not flag only-final fields in enum body', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color {',
        '  RED, GREEN, BLUE;',
        '  private final String label;',
        '  private final String name;',
        '  String getLabel() { return label; }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.mutableEnumFields,
      ),
    ).toHaveLength(0);
  });

  it('flags @NoAllocation method that creates objects', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  @NoAllocation',
        '  String bad() {',
        '    return new String("alloc");',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.noAllocationMethodCreatesObject,
    );
  });

  it('does not flag @NoAllocation method without allocation', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  @NoAllocation',
        '  String good() {',
        '    return "literal";',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.noAllocationMethodCreatesObject,
      ),
    ).toHaveLength(0);
  });

  it('does not flag method without @NoAllocation that creates objects', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  String normal() {',
        '    return new String("ok");',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.noAllocationMethodCreatesObject,
      ),
    ).toHaveLength(0);
  });

  // --- Batch 14 (JAVA-E) tests ---

  it('flags collection.contains(self) for E1076', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    java.util.List<String> strings = java.util.List.of("a");',
        '    if (strings.contains(strings)) {}',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.collectionContainsSelf,
    );
  });

  it('does not flag collection.contains(other) for E1076', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    java.util.List<String> strings = java.util.List.of("a");',
        '    java.util.List<String> other = java.util.List.of("b");',
        '    if (strings.containsAll(other)) {}',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.collectionContainsSelf,
      ),
    ).toHaveLength(0);
  });

  it('flags collection.add(self) for E1077', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    java.util.List<String> strings = new java.util.ArrayList<>();',
        '    strings.add(strings);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.collectionAddsSelf,
    );
  });

  it('does not flag collection.add(other) for E1077', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    java.util.List<String> strings = new java.util.ArrayList<>();',
        '    java.util.List<String> other = new java.util.ArrayList<>();',
        '    strings.addAll(other);',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.collectionAddsSelf,
      ),
    ).toHaveLength(0);
  });

  it('flags ambiguous modulus-multiplication precedence for E1080', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int m(int i) {',
        '    return i % 60 * 1000;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.modulusMultiplicationPrecedence,
    );
  });

  it('does not flag explicit (mod * mult) for E1080', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  int m(int i) {',
        '    return (i % 60) * 1000;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.modulusMultiplicationPrecedence,
      ),
    ).toHaveLength(0);
  });

  it('flags bitwise OR never equal for E1073', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean m(int flags) {',
        '    return (flags | 2) == 1;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.bitwiseOrNeverEqual,
    );
  });

  it('does not flag bitwise OR that can equal for E1073', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  boolean m(int flags) {',
        '    return (flags | 4) == 4;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) => f.kind === JAVA_CORRECTNESS_FACT_KINDS.bitwiseOrNeverEqual,
      ),
    ).toHaveLength(0);
  });

  it('flags getter/setter sync mismatch for E1074', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private int field;',
        '  synchronized int getField() { return field; }',
        '  void setField(int v) { field = v; }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.getterSetterSyncMismatch,
    );
  });

  it('does not flag both getter/setter synchronized for E1074', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private int field;',
        '  synchronized int getField() { return field; }',
        '  synchronized void setField(int v) { field = v; }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.getterSetterSyncMismatch,
      ),
    ).toHaveLength(0);
  });

  it('does not flag neither getter/setter synchronized for E1074', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  private int field;',
        '  int getField() { return field; }',
        '  void setField(int v) { field = v; }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.getterSetterSyncMismatch,
      ),
    ).toHaveLength(0);
  });

  // Batch 15 (NEW) — JAVA-E1082, E1095, E1103, E1108

  it('flags deprecated ThreadGroup instance methods (E1108)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    ThreadGroup tg = new ThreadGroup("x");',
        '    tg.suspend();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.threadGroupDeprecatedMethods,
    );
  });

  it('flags deprecated ThreadGroup static methods (E1108)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    ThreadGroup.stop();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.threadGroupDeprecatedMethods,
    );
  });

  it('does not flag Thread methods as ThreadGroup (E1108)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Demo {',
        '  void m() {',
        '    Thread.currentThread().suspend();',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind ===
          JAVA_CORRECTNESS_FACT_KINDS.threadGroupDeprecatedMethods,
      ),
    ).toHaveLength(0);
  });

  it('flags @Provides method returning Closeable type (E1103)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Module {',
        '  @Provides',
        '  FileOutputStream provideStream() {',
        '    return new FileOutputStream("out");',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.closeableProvidesInjection,
    );
  });

  it('flags @Inject method returning Closeable type (E1103)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Module {',
        '  @Inject',
        '  Connection createConnection() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.closeableProvidesInjection,
    );
  });

  it('does not flag @Provides returning non-Closeable (E1103)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Module {',
        '  @Provides',
        '  String getName() {',
        '    return "test";',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.closeableProvidesInjection,
      ),
    ).toHaveLength(0);
  });

  it('flags @Nonnull method returning null (E1095)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  @Nonnull',
        '  String m() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.nonNullMethodReturnsNull,
    );
  });

  it('does not flag @Nonnull method returning non-null (E1095)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  @Nonnull',
        '  String m() {',
        '    return "hello";',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.nonNullMethodReturnsNull,
      ),
    ).toHaveLength(0);
  });

  it('does not flag unannotated method returning null (E1095)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'class Test {',
        '  String m() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.nonNullMethodReturnsNull,
      ),
    ).toHaveLength(0);
  });

  it('flags switch on enum missing elements without default (E1082)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color { RED, BLUE }',
        'class Test {',
        '  void m(Color c) {',
        '    switch(c) {',
        '      case RED: break;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(facts.map((f) => f.kind)).toContain(
      JAVA_CORRECTNESS_FACT_KINDS.missingEnumSwitchElements,
    );
  });

  it('does not flag switch with all enum members covered (E1082)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color { RED, BLUE }',
        'class Test {',
        '  void m(Color c) {',
        '    switch(c) {',
        '      case RED: break;',
        '      case BLUE: break;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.missingEnumSwitchElements,
      ),
    ).toHaveLength(0);
  });

  it('does not flag switch with default label (E1082)', () => {
    const facts = collectJavaCorrectnessFacts({
      detector: 'java-detector',
      text: [
        'enum Color { RED, BLUE }',
        'class Test {',
        '  void m(Color c) {',
        '    switch(c) {',
        '      case RED: break;',
        '      default: break;',
        '    }',
        '  }',
        '}',
      ].join('\n'),
    });
    expect(
      facts.filter(
        (f) =>
          f.kind === JAVA_CORRECTNESS_FACT_KINDS.missingEnumSwitchElements,
      ),
    ).toHaveLength(0);
  });
});
