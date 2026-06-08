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
});
