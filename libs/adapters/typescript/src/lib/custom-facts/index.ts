import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  collectInsecureCookieJwtSessionFacts,
} from './insecure-cookie-jwt-session';
import { collectInsecureTransportFacts } from './insecure-transport';
import { collectOpenRedirectFacts } from './open-redirect';
import { detectReactNextBestPracticesFacts } from './react-next-best-practices';
import { collectSensitiveEgressFacts } from './sensitive-egress';
import { collectSensitiveLoggingFacts } from './sensitive-logging';
import { collectSsrfFacts } from './ssrf';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectWeakCryptoFacts } from './weak-crypto';

export function collectAdditionalTypeScriptFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectInsecureCookieJwtSessionFacts(context),
    ...collectInsecureTransportFacts(context),
    ...collectOpenRedirectFacts(context),
    ...detectReactNextBestPracticesFacts(context),
    ...collectSensitiveEgressFacts(context),
    ...collectSensitiveLoggingFacts(context),
    ...collectSsrfFacts(context),
    ...collectWeakCryptoFacts(context),
  ].sort((left, right) => {
    if (left.range.startLine !== right.range.startLine) {
      return left.range.startLine - right.range.startLine;
    }

    if (left.range.startColumn !== right.range.startColumn) {
      return left.range.startColumn - right.range.startColumn;
    }

    return left.kind.localeCompare(right.kind);
  });
}
