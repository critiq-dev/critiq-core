import {
  collectDynamodbClientBindings,
  collectExpressModelBindings,
  collectRequestDerivedNames,
  collectUploadDerivedNames,
  collectValidatedTrustBoundaryState,
  resolveFunctionBindings,
} from './additional-public-security/analysis';
import {
  collectDatadogBrowserFacts,
  collectExpressHardeningFacts,
  collectHardcodedAuthSecretFacts,
  collectRenderFacts,
} from './additional-public-security/application';
import {
  collectDebugModeEnabledFacts,
  collectInformationLeakageFacts,
} from './additional-public-security/disclosure';
import {
  collectDynamodbQueryFacts,
  collectFileAndExceptionFacts,
  collectNosqlInjectionFacts,
  collectObservableTimingFacts,
} from './additional-public-security/data';
import { collectFilesystemSafetyFacts } from './additional-public-security/filesystem';
import {
  collectHtmlOutputFacts,
  collectHttpResponseFacts,
} from './additional-public-security/html';
import {
  collectBrowserOriginFacts,
  collectFormatStringFacts,
  collectHeaderMisuseFacts,
  collectModuleLoadFacts,
  collectWebsocketFacts,
} from './additional-public-security/transport';
import { type TypeScriptFactDetector } from './shared';

export const collectAdditionalPublicSecurityFacts: TypeScriptFactDetector = (
  context,
) => {
  const taintedNames = collectRequestDerivedNames(context);
  const uploadDerivedNames = collectUploadDerivedNames(context);
  const validatedTrustBoundaries = collectValidatedTrustBoundaryState(context);
  const functionBindings = resolveFunctionBindings(context);
  const modelNames = collectExpressModelBindings(context);
  const dynamodbClientNames = collectDynamodbClientBindings(context);

  return [
    ...collectFilesystemSafetyFacts(context, taintedNames, uploadDerivedNames),
    ...collectHeaderMisuseFacts(context, taintedNames, functionBindings),
    ...collectNosqlInjectionFacts(context, taintedNames, modelNames),
    ...collectDynamodbQueryFacts(context, taintedNames, dynamodbClientNames),
    ...collectInformationLeakageFacts(context),
    ...collectFormatStringFacts(context, taintedNames),
    ...collectBrowserOriginFacts(context, functionBindings),
    ...collectModuleLoadFacts(
      context,
      taintedNames,
      validatedTrustBoundaries,
    ),
    ...collectHttpResponseFacts(context, taintedNames),
    ...collectHtmlOutputFacts(context, taintedNames),
    ...collectWebsocketFacts(context),
    ...collectHardcodedAuthSecretFacts(context),
    ...collectFileAndExceptionFacts(context),
    ...collectObservableTimingFacts(context),
    ...collectRenderFacts(
      context,
      taintedNames,
      validatedTrustBoundaries,
    ),
    ...collectDatadogBrowserFacts(context),
    ...collectExpressHardeningFacts(context, functionBindings),
    ...collectDebugModeEnabledFacts(context),
  ];
};
