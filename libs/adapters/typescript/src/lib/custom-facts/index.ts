import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  collectAdditionalPublicSecurityFacts,
} from './additional-public-security';
import {
  collectClientApplicationSecurityFacts,
} from './client-application-security';
import {
  collectInsecureCookieJwtSessionFacts,
} from './insecure-cookie-jwt-session';
import { collectInsecureTransportFacts } from './insecure-transport';
import { collectNetworkExposureFacts } from './network-exposure';
import { collectOpenRedirectFacts } from './open-redirect';
import { collectPhase1PolyglotSecurityFacts } from './phase1-polyglot-security';
import { detectReactAccessibilityFacts } from './react-accessibility';
import { detectReactNextBestPracticesFacts } from './react-next-best-practices';
import { collectNestJsSecurityFacts } from './nestjs-security';
import { collectNextServerActionFacts } from './next-server-actions';
import { collectSensitiveEgressFacts } from './sensitive-egress';
import { collectSensitiveLoggingFacts } from './sensitive-logging';
import { collectSsrfFacts } from './ssrf';
import { collectTypescriptTestingHygieneFacts } from './typescript-testing-hygiene';
import { collectQueryCommandDynamicExecutionFacts } from './query-command-dynamic-execution';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectWeakCryptoFacts } from './weak-crypto';

export function collectAdditionalTypeScriptFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts = [
    ...collectAdditionalPublicSecurityFacts(context),
    ...collectClientApplicationSecurityFacts(context),
    ...collectInsecureCookieJwtSessionFacts(context),
    ...collectInsecureTransportFacts(context),
    ...collectNetworkExposureFacts(context),
    ...collectOpenRedirectFacts(context),
    ...collectQueryCommandDynamicExecutionFacts(context),
    ...collectPhase1PolyglotSecurityFacts(context),
    ...collectNextServerActionFacts(context),
    ...detectReactNextBestPracticesFacts(context),
    ...detectReactAccessibilityFacts(context),
    ...collectSensitiveEgressFacts(context),
    ...collectTypescriptTestingHygieneFacts(context),
    ...collectSensitiveLoggingFacts(context),
    ...collectSsrfFacts(context),
    ...collectNestJsSecurityFacts(context),
    ...collectWeakCryptoFacts(context),
  ];
  const uniqueFacts = new Map<string, ObservedFact>();

  for (const fact of facts) {
    if (!uniqueFacts.has(fact.id)) {
      uniqueFacts.set(fact.id, fact);
    }
  }

  return [...uniqueFacts.values()].sort((left, right) => {
    if (left.range.startLine !== right.range.startLine) {
      return left.range.startLine - right.range.startLine;
    }

    if (left.range.startColumn !== right.range.startColumn) {
      return left.range.startColumn - right.range.startColumn;
    }

    return left.kind.localeCompare(right.kind);
  });
}
