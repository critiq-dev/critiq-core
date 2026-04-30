import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './shared';

const defaultAndroidWorldReadablePattern =
  /\b(?:Context\.)?MODE_WORLD_(?:READABLE|WRITABLE|WRITEABLE)\b/g;

export interface AndroidWorldReadableModeOptions {
  appliesTo?: ObservedFact['appliesTo'];
  detector: string;
  pattern?: RegExp;
  text: string;
}

export function collectAndroidWorldReadableModeFacts(
  options: AndroidWorldReadableModeOptions,
): ObservedFact[] {
  return collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.android-world-readable-mode',
    pattern: options.pattern ?? defaultAndroidWorldReadablePattern,
    appliesTo: options.appliesTo ?? 'block',
    props: ({ matchedText }) => ({
      mode: matchedText.trim(),
    }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });
}
