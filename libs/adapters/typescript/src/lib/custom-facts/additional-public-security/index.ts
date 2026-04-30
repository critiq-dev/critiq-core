import {
  collectDynamodbClientBindings,
  collectExpressModelBindings,
  collectRequestDerivedNames,
  collectUploadDerivedNames,
  collectValidatedTrustBoundaryState,
  resolveFunctionBindings,
} from './analysis';
import {
  collectDatadogBrowserFacts,
  collectExpressHardeningFacts,
  collectHardcodedAuthSecretFacts,
  collectRenderFacts,
} from './application';
import {
  collectDebugModeEnabledFacts,
  collectInformationLeakageFacts,
} from './disclosure';
import {
  collectDynamodbQueryFacts,
  collectFileAndExceptionFacts,
  collectNosqlInjectionFacts,
  collectObservableTimingFacts,
} from './data';
import { collectFilesystemSafetyFacts } from './filesystem';
import {
  collectHtmlOutputFacts,
  collectHttpResponseFacts,
} from './html';
import {
  collectBrowserOriginFacts,
  collectFormatStringFacts,
  collectHeaderMisuseFacts,
  collectModuleLoadFacts,
  collectWebsocketFacts,
} from './transport';
import { type TypeScriptFactDetector } from '../shared';

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
