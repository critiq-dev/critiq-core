import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectAngularJsFacts } from './angularjs';
import {
  collectAdditionalPublicSecurityFacts,
} from './additional-public-security';
import { collectElectronShellOpenExternalUnvalidatedFacts } from './additional-public-security/electron-shell-open-external-unvalidated';
import { collectClientApplicationSecurityFacts } from './client-application-security';
import { collectTypescriptAsyncCorrectnessFacts } from './typescript-async-correctness';
import { collectTypescriptCoreLanguageCorrectnessFacts } from './typescript-core-language-correctness';
import { collectTypescriptClassAndSyntaxCorrectnessFacts } from './typescript-class-and-syntax-correctness';
import { collectTypescriptCorrectnessLanguageExtendedFacts } from './typescript-correctness-language-extended';
import { collectTypescriptLanguageCorrectnessExtendedFacts } from './typescript-language-correctness-extended';
import { collectTypescriptScopeCorrectnessFacts } from './typescript-scope-correctness';
import {
  collectInsecureCookieJwtSessionFacts,
} from './insecure-cookie-jwt-session';
import { collectInsecureTransportFacts } from './insecure-transport';
import { collectInsecureServerListenFacts } from './insecure-server-listen';
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
import { collectTypescriptQualityMaintainabilityFacts } from './typescript-quality-maintainability';
import { collectTypescriptPerformanceFacts } from './typescript-performance';
import { collectQueryCommandDynamicExecutionFacts } from './query-command-dynamic-execution';
import { collectSyncChildProcessExecFactsDetector } from './sync-child-process-exec';
import { collectTypescriptRuntimeSecurityFacts } from './typescript-runtime-security';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectUserControlledRegexpFacts } from './user-controlled-regexp';
import { collectWeakCryptoFacts } from './weak-crypto';
import { collectVueDeprecationFacts } from './vue-deprecation-facts';
import { collectVueFacts } from './vue';
import { collectVueNuxtLifecycleFacts } from './vue-nuxt-lifecycle-facts';
import { collectVueNuxtCorrectnessFacts } from './vue-nuxt-correctness-facts';
import { collectNextImportRulesFacts } from './next-import-rules';
import { collectDuplicateExportFacts } from './typescript-export-correctness';
import { collectTypescriptUselessAssertionFacts } from './typescript-testing-useless-assertions';

export function collectAdditionalTypeScriptFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts = [
    ...collectAngularJsFacts(context),
    ...collectAdditionalPublicSecurityFacts(context),
    ...collectClientApplicationSecurityFacts(context),
    ...collectElectronShellOpenExternalUnvalidatedFacts(context),
    ...collectTypescriptAsyncCorrectnessFacts(context),
    ...collectTypescriptCoreLanguageCorrectnessFacts(context),
    ...collectTypescriptCorrectnessLanguageExtendedFacts(context),
    ...collectTypescriptLanguageCorrectnessExtendedFacts(context),
    ...collectTypescriptScopeCorrectnessFacts(context),
    ...collectTypescriptClassAndSyntaxCorrectnessFacts(context),
    ...collectInsecureCookieJwtSessionFacts(context),
    ...collectInsecureTransportFacts(context),
    ...collectInsecureServerListenFacts(context),
    ...collectNetworkExposureFacts(context),
    ...collectOpenRedirectFacts(context),
    ...collectQueryCommandDynamicExecutionFacts(context),
    ...collectSyncChildProcessExecFactsDetector(context),
    ...collectTypescriptRuntimeSecurityFacts(context),
    ...collectPhase1PolyglotSecurityFacts(context),
    ...collectNextServerActionFacts(context),
    ...detectReactNextBestPracticesFacts(context),
    ...detectReactAccessibilityFacts(context),
    ...collectSensitiveEgressFacts(context),
    ...collectTypescriptTestingHygieneFacts(context),
    ...collectTypescriptQualityMaintainabilityFacts(context),
    ...collectTypescriptPerformanceFacts(context),
    ...collectSensitiveLoggingFacts(context),
    ...collectSsrfFacts(context),
    ...collectNestJsSecurityFacts(context),
    ...collectWeakCryptoFacts(context),
    ...collectUserControlledRegexpFacts(context),
    ...collectVueFacts(context),
    ...collectVueDeprecationFacts(context),
    ...collectVueNuxtLifecycleFacts(context),
    ...collectVueNuxtCorrectnessFacts(context),
    ...collectNextImportRulesFacts(context),
    ...collectDuplicateExportFacts(context),
    ...collectTypescriptUselessAssertionFacts(context),
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
