import {
  collectRustQualityFacts,
  RUST_QUALITY_FACT_KINDS,
} from './rust-quality';

describe('rust-quality collectors (RS-W)', () => {
  // ── RS-W1086: Potentially incomplete ASCII range ──

  it('flags exclusive ASCII range `..` between chars (RS-W1086)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: "for letter in 'a'..'z' { let _ = letter; }",
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.potentiallyIncompleteAsciiRange,
    );
  });

  it('does not flag inclusive ASCII range `..=` (RS-W1086)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: "for letter in 'a'..='z' { let _ = letter; }",
    });

    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_QUALITY_FACT_KINDS.potentiallyIncompleteAsciiRange,
      ),
    ).toHaveLength(0);
  });

  it('does not flag numeric range (RS-W1086)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'for i in 0..10 { let _ = i; }',
    });

    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_QUALITY_FACT_KINDS.potentiallyIncompleteAsciiRange,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1087: Inaccurate duration calculation ──

  it('flags subsec_micros() / 1_000 (RS-W1087)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let millis = duration.subsec_micros() / 1_000;',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.inaccurateDurationCalculation,
    );
  });

  it('flags subsec_nanos() / 1_000 (RS-W1087)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let millis = duration.subsec_nanos() / 1_000;',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.inaccurateDurationCalculation,
    );
  });

  it('does not flag subsec_millis() direct call (RS-W1087)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let millis = duration.subsec_millis();',
    });

    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_QUALITY_FACT_KINDS.inaccurateDurationCalculation,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1089: Map followed by count ──

  it('flags .map().count() chain (RS-W1089)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: '(0..5).map(|i| i > 2).count();',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.mapFollowedByCount,
    );
  });

  it('does not flag .filter().count() chain (RS-W1089)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: '(0..5).filter(|i| i > 2).count();',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.mapFollowedByCount,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1091: .iter().nth() instead of .get() ──

  it('flags .iter().nth() (RS-W1091)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let x = v.iter().nth(2);',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.iterNthInsteadOfGet,
    );
  });

  it('flags .iter_mut().nth() (RS-W1091)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let x = v.iter_mut().nth(2);',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.iterNthInsteadOfGet,
    );
  });

  it('does not flag .get() (RS-W1091)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let x = v.get(2);',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.iterNthInsteadOfGet,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1093: .iter().count() instead of .len() ──

  it('flags .iter().count() (RS-W1093)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let count = map.iter().count();',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.iterCountInsteadOfLen,
    );
  });

  it('does not flag .len() (RS-W1093)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let count = map.len();',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.iterCountInsteadOfLen,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1094: Replace with same pattern and replacement ──

  it('flags .replace() with same pattern and replacement (RS-W1094)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let t = text.replace(\'a\', \'a\');',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.replaceSamePatternAndReplacement,
    );
  });

  it('does not flag .replace() with different pattern and replacement (RS-W1094)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let t = text.replace(\'a\', \'b\');',
    });

    expect(
      facts.filter(
        (f) =>
          f.kind === RUST_QUALITY_FACT_KINDS.replaceSamePatternAndReplacement,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1100: Clone on double reference ──

  it('flags .clone() inside closure (RS-W1100)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let v = t.iter().map(|x| x.clone()).collect::<Vec<_>>();',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.cloneOnDoubleReference,
    );
  });

  it('does not flag explicit deref then clone (RS-W1100)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let v = t.iter().map(|x| (*x).clone()).collect::<Vec<_>>();',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.cloneOnDoubleReference,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1106: Non-owned Rc pointer into vec ──

  it('flags Rc::new() then .clone() push (RS-W1106)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let rcp = Rc::new(10); v.push(rcp.clone());',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.nonOwnedRcPointerIntoVec,
    );
  });

  it('does not flag Rc::new() inside push (RS-W1106)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'v.push(Rc::new(10));',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.nonOwnedRcPointerIntoVec,
      ),
    ).toHaveLength(0);
  });

  // ── Path suppression ──

  // ── RS-W1013: Explicit self-assignment ──

  it('flags explicit self-assignment `x = x;` (RS-W1013)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let mut x = 1; x = x; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.explicitSelfAssignment,
    );
  });

  it('flags explicit self-assignment `self.field = self.field;` (RS-W1013)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn set(&mut self) { self.field = self.field; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.explicitSelfAssignment,
    );
  });

  it('does not flag `let x = x;` (shadow rebind, not self-assignment) (RS-W1013)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f(x: i32) { let x = x; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.explicitSelfAssignment),
    ).toHaveLength(0);
  });

  it('does not flag self-assignment inside destructure (RS-W1013)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let (a, b) = (1, 2); let _ = a; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.explicitSelfAssignment),
    ).toHaveLength(0);
  });

  // ── RS-W1015: String literal in env functions ──

  it('flags `env!()` with non-uppercase string literal (RS-W1015)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let _ = env!("debug_mode");',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.envStringLiteral,
    );
  });

  it('does not flag `env!()` with uppercase env var name (RS-W1015)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let _ = env!("PATH");',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.envStringLiteral),
    ).toHaveLength(0);
  });

  it('does not flag `env!()` with dotted uppercase name (RS-W1015)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let _ = env!("JAVA_HOME");',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.envStringLiteral),
    ).toHaveLength(0);
  });

  // ── RS-W1016: unwrap on option_env! ──

  it('flags `option_env!("...").unwrap()` (RS-W1016)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let _ = option_env!("HOME").unwrap();',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.optionEnvUnwrap,
    );
  });

  it('does not flag `option_env!("...").unwrap_or()` (RS-W1016)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'let _ = option_env!("HOME").unwrap_or("default");',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.optionEnvUnwrap),
    ).toHaveLength(0);
  });

  // ── RS-W1028: Builtin-type shadow ──

  it('flags `let String = ...` shadowing built-in type (RS-W1028)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let String = 5; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.builtinTypeShadow,
    );
  });

  it('flags `let i32 = ...` shadowing built-in type (RS-W1028)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let i32 = "hello"; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.builtinTypeShadow,
    );
  });

  it('does not flag `let my_var = ...` (not a built-in type) (RS-W1028)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let my_var = 5; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.builtinTypeShadow),
    ).toHaveLength(0);
  });

  // ── RS-W1039: Unused enumerate or zip items ──

  it('flags unused enumerate index in for loop (RS-W1039)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: "fn f() { for (idx, val) in items.iter().enumerate() { println!('{val}'); } }",
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.unusedEnumerateOrZipItems,
    );
  });

  it('does not flag unused enumerate with `_` (RS-W1039)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: "fn f() { for (_, val) in items.iter().enumerate() { println!('{val}'); } }",
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.unusedEnumerateOrZipItems),
    ).toHaveLength(0);
  });

  it('does not flag enumerate index used in body (RS-W1039)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: "fn f() { for (idx, val) in items.iter().enumerate() { println!('{idx}: {val}'); } }",
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.unusedEnumerateOrZipItems),
    ).toHaveLength(0);
  });

  // ── RS-W1075: isize/usize enumeration overflow ──

  it('flags `0..=isize::MAX` in range (RS-W1075)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { for i in 0..=isize::MAX { let _ = i; } }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.isizeUsizeOverflow,
    );
  });

  it('does not flag `isize::MAX` outside a range (RS-W1075)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let max = isize::MAX; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.isizeUsizeOverflow),
    ).toHaveLength(0);
  });

  // ── RS-W1081: Ordered iteration on unordered collection ──

  it('flags `.iter().sorted()` on HashMap (RS-W1081)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f(m: &HashMap<String, i32>) { for (k, v) in m.iter().sorted() { let _ = (k, v); } }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.orderedIterationOnUnordered,
    );
  });

  it('does not flag `.iter().sorted()` on BTreeMap (RS-W1081)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f(m: &BTreeMap<String, i32>) { for (k, v) in m.iter() { let _ = (k, v); } }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.orderedIterationOnUnordered),
    ).toHaveLength(0);
  });

  // ── RS-W1084: `crate` in macro definition ──

  it('flags `crate::` usage inside macro_rules! (RS-W1084)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'macro_rules! my_macro { ($x:expr) => { crate::my_fn($x); }; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.crateInMacroDefinition,
    );
  });

  it('does not flag `$crate::` usage inside macro_rules! (RS-W1084)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'macro_rules! my_macro { ($x:expr) => { $crate::my_fn($x); }; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.crateInMacroDefinition),
    ).toHaveLength(0);
  });

  it('does not flag `crate::` outside macro_rules! (RS-W1084)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { crate::my_fn(); }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.crateInMacroDefinition),
    ).toHaveLength(0);
  });

  // ── Path suppression ──

  // ── RS-W1112: Redundant mem::replace with None ──

  it('flags `mem::replace(&mut opt, None)` (RS-W1112)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::replace(&mut opt, None); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithNone,
    );
  });

  it('does not flag `opt.take()` (RS-W1112)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = opt.take(); }',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithNone,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1113: Redundant mem::replace with Default ──

  it('flags `mem::replace(&mut val, Default::default())` (RS-W1113)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::replace(&mut val, Default::default()); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithDefault,
    );
  });

  it('does not flag `mem::take()` (RS-W1113)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::take(&mut val); }',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithDefault,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1114: Redundant mem::replace with zero ──

  it('flags `mem::replace(&mut val, 0)` (RS-W1114)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::replace(&mut val, 0); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithZero,
    );
  });

  it('flags `mem::replace(&mut val, false)` (RS-W1114)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::replace(&mut val, false); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithZero,
    );
  });

  it('does not flag `mem::take()` (RS-W1114)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = std::mem::take(&mut val); }',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.redundantMemReplaceWithZero,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1115: Function pointer null comparison ──

  it('flags `fn_ptr as usize == 0` (RS-W1115)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { if (my_fn as usize == 0) { } }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.fnPtrNullComparison,
    );
  });

  it('does not flag normal fn ptr usage (RS-W1115)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = my_fn as *const (); }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.fnPtrNullComparison),
    ).toHaveLength(0);
  });

  // ── RS-W1121: Possible missing comma in array ──

  it('flags missing comma in array `[1, 2 3]` (RS-W1121)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = [1, 2 3]; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.possibleMissingCommaInArray,
    );
  });

  it('does not flag correct comma usage in array (RS-W1121)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = [1, 2, 3]; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.possibleMissingCommaInArray),
    ).toHaveLength(0);
  });

  // ── RS-W1122: Non-UTF-8 in from_utf8_unchecked ──

  it('flags non-UTF-8 byte literal in from_utf8_unchecked (RS-W1122)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let s = unsafe { str::from_utf8_unchecked(b"hello\\xffworld") }; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.nonUtf8LiteralInFromUtf8Unchecked,
    );
  });

  it('does not flag valid UTF-8 in from_utf8_unchecked (RS-W1122)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let s = unsafe { str::from_utf8_unchecked(b"hello") }; }',
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_QUALITY_FACT_KINDS.nonUtf8LiteralInFromUtf8Unchecked,
      ),
    ).toHaveLength(0);
  });

  // ── RS-W1123: size_of_val on reference ──

  it('flags `mem::size_of_val(&var)` (RS-W1123)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let s = std::mem::size_of_val(&x); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.sizeOfValOnReference,
    );
  });

  it('does not flag `mem::size_of_val(x)` without address-of (RS-W1123)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let s = std::mem::size_of_val(x); }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.sizeOfValOnReference),
    ).toHaveLength(0);
  });

  // ── RS-W1124: Function pointer to non-pointer cast ──

  it('flags `my_fn as usize` cast (RS-W1124)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = my_fn as usize; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.fnPtrToNonPointerCast,
    );
  });

  it('does not flag `my_fn as *const ()` cast (RS-W1124)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let _ = my_fn as *const (); }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.fnPtrToNonPointerCast),
    ).toHaveLength(0);
  });

  // ── RS-W1128: Deprecated function use ──

  it('flags `std::mem::uninitialized()` usage (RS-W1128)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = std::mem::uninitialized::<i32>(); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse,
    );
  });

  it('flags `std::sync::ONCE_INIT` usage (RS-W1128)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'static INIT: std::sync::Once = std::sync::ONCE_INIT;',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse,
    );
  });

  it('flags `std::thread::sleep_ms` usage (RS-W1128)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { std::thread::sleep_ms(100); }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse,
    );
  });

  it('flags `ONCE_INIT` shorthand usage (RS-W1128)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'static INIT: Once = ONCE_INIT;',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse,
    );
  });

  it('does not flag normal function calls (RS-W1128)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = std::mem::replace(&mut v, 0); }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.deprecatedFunctionUse),
    ).toHaveLength(0);
  });

  // ── RS-W1207: Manual approximation of floating constant ──

  it('flags `3.1415` as approximate PI (RS-W1207)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = 3.1415; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.approximateFloatingConstant,
    );
  });

  it('flags `2.718` as approximate E (RS-W1207)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = 2.718; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.approximateFloatingConstant,
    );
  });

  it('flags `6.2831` as approximate TAU (RS-W1207)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = 6.2831; }',
    });

    expect(facts.map((f) => f.kind)).toContain(
      RUST_QUALITY_FACT_KINDS.approximateFloatingConstant,
    );
  });

  it('does not flag `42.0` (not a known constant) (RS-W1207)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = 42.0; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.approximateFloatingConstant),
    ).toHaveLength(0);
  });

  it('does not flag integer literals (RS-W1207)', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      text: 'fn f() { let x = 42; }',
    });

    expect(
      facts.filter((f) => f.kind === RUST_QUALITY_FACT_KINDS.approximateFloatingConstant),
    ).toHaveLength(0);
  });

  // ── Path suppression ──

  it('returns no facts for suppressed test paths', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      path: 'tests/integration_test.rs',
      text: "for letter in 'a'..'z' { let _ = letter; }",
    });

    expect(facts).toHaveLength(0);
  });
});
