import type { ObservedFact } from '@critiq/core-rules-engine';

import { dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { isRustSecuritySuppressedPath } from './rust-general-security';

export const RUST_SECURITY_UNSAFE_CODE_FACT_KINDS = {
  constToMutPtr: 'rust.security.const-to-mut-ptr',
  rawSliceToPtr: 'rust.security.raw-slice-to-ptr',
  differentlySizedSliceConversion:
    'rust.security.differently-sized-slice-conversion',
} as const;

export interface CollectRustSecurityUnsafeCodeFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRustSecurityUnsafeCodeFacts(
  options: CollectRustSecurityUnsafeCodeFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path !== undefined && isRustSecuritySuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectConstToMutPtrFacts(text, detector),
    ...collectRawSliceToPtrFacts(text, detector),
    ...collectDifferentlySizedSliceConversionFacts(text, detector),
  ]);
}

function collectConstToMutPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.constToMutPtr,
    appliesTo: 'block',
    pattern: /\w+\s+as\s+\*mut\b/g,
  });
}

function collectRawSliceToPtrFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.rawSliceToPtr,
    appliesTo: 'block',
    pattern: /(?:&\w+\[\.\.\]|&mut\s+\w+\[\.\.\])\s+as\s+\*[cm]onst\b/g,
  });
}

function collectDifferentlySizedSliceConversionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_SECURITY_UNSAFE_CODE_FACT_KINDS.differentlySizedSliceConversion;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /as\s+\*[cm]onst\s+\[(?:u8|u16|u32|u64|i8|i16|i32|i64|f32|f64)\]/g,
  });
}
