import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

const defaultAndroidActivityPattern =
  /\bclass\s+[A-Za-z_][A-Za-z0-9_]*\s+extends\s+(?:[A-Za-z_][A-Za-z0-9_]*Activity|Activity|AppCompatActivity|ComponentActivity|FragmentActivity)\b/g;
const secureFlagEnabledPattern =
  /\b(?:getWindow\(\)\.)?(?:addFlags|setFlags)\s*\([^;\n]*FLAG_SECURE\b/g;
const secureFlagClearedPattern =
  /\b(?:getWindow\(\)\.)?clearFlags\s*\([^;\n]*FLAG_SECURE\b/g;
const sensitiveAndroidScreenPattern =
  /\b(?:account|auth|balance|billing|card|credential|login|otp|password|payment|pin|secret|session|token|transfer|wallet)\b|[A-Za-z0-9_]*(?:Otp|Passcode|Password|Pin|Secret|Session|Token)\b/i;

export interface AndroidScreenshotExposureOptions {
  activityPattern?: RegExp;
  appliesTo?: ObservedFact['appliesTo'];
  detector: string;
  text: string;
}

export function collectAndroidScreenshotExposureFacts(
  options: AndroidScreenshotExposureOptions,
): ObservedFact[] {
  const hasSecureFlag = secureFlagEnabledPattern.test(options.text);
  const hasClearedSecureFlag = secureFlagClearedPattern.test(options.text);

  if (hasSecureFlag && !hasClearedSecureFlag) {
    return [];
  }

  if (!hasClearedSecureFlag && !sensitiveAndroidScreenPattern.test(options.text)) {
    return [];
  }

  return collectMatchedFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.android-screenshot-exposure',
    pattern: options.activityPattern ?? defaultAndroidActivityPattern,
    appliesTo: options.appliesTo ?? 'file',
    props: () => ({
      reason: hasClearedSecureFlag ? 'flag-secure-cleared' : 'flag-secure-missing',
    }),
    textValue: ({ matchedText }) => matchedText.trim(),
  });
}
