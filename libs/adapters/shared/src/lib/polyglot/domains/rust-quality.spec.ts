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

  it('returns no facts for suppressed test paths', () => {
    const facts = collectRustQualityFacts({
      detector: 'rust-detector',
      path: 'tests/integration_test.rs',
      text: "for letter in 'a'..'z' { let _ = letter; }",
    });

    expect(facts).toHaveLength(0);
  });
});
