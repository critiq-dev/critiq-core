import {
  collectRustSecurityUnsafeCodeFacts,
  RUST_SECURITY_UNSAFE_CODE_FACT_KINDS,
} from './rust-security-unsafe-code';

describe('rust-security-unsafe-code collectors', () => {
  const detector = 'rust-detector';

  it('flags const to mut pointer conversion (RS-S1011)', () => {
    const facts = collectRustSecurityUnsafeCodeFacts({
      detector,
      text: [
        'fn unsafe_cast(ptr: *const u8) -> *mut u8 {',
        '    unsafe {',
        '        ptr as *mut u8',
        '    }',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.constToMutPtr,
      ).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('flags raw slice to pointer conversion (RS-S1012)', () => {
    const facts = collectRustSecurityUnsafeCodeFacts({
      detector,
      text: [
        'fn to_ptr(data: &[u8]) -> *const u8 {',
        '    &data[..] as *const u8',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) => f.kind === RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.rawSliceToPtr,
      ).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('flags differently sized slice conversion (RS-S1013)', () => {
    const facts = collectRustSecurityUnsafeCodeFacts({
      detector,
      text: [
        'fn reinterpret(s: *const [u32]) -> *const [u8] {',
        '    s as *const [u8]',
        '}',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (f) =>
          f.kind ===
          RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.differentlySizedSliceConversion,
      ).length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('returns empty for clean code', () => {
    const facts = collectRustSecurityUnsafeCodeFacts({
      detector,
      text: [
        'fn safe(data: &[u8]) -> &[u8] {',
        '    data',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });

  it('returns empty for test path', () => {
    const facts = collectRustSecurityUnsafeCodeFacts({
      detector,
      path: 'src/main_test.rs',
      text: [
        'fn unsafe_cast(ptr: *const u8) -> *mut u8 {',
        '    unsafe { ptr as *mut u8 }',
        '}',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
