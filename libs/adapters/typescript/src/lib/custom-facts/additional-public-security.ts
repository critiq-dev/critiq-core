import {
  collectDynamodbClientBindings,
  collectExpressModelBindings,
  collectRequestDerivedNames,
  resolveFunctionBindings,
} from './additional-public-security/analysis';
import {
  collectDatadogBrowserFacts,
  collectExpressHardeningFacts,
  collectHardcodedAuthSecretFacts,
  collectRenderAndSendFileFacts,
} from './additional-public-security/application';
import {
  collectDynamodbQueryFacts,
  collectFileAndExceptionFacts,
  collectFilePermissionFacts,
  collectNosqlInjectionFacts,
  collectObservableTimingFacts,
} from './additional-public-security/data';
import {
  collectBrowserOriginFacts,
  collectFormatStringFacts,
  collectHeaderMisuseFacts,
  collectHtmlAndWebsocketFacts,
  collectHttpResponseFacts,
  collectModuleLoadFacts,
} from './additional-public-security/transport';
import { type TypeScriptFactDetector } from './shared';

export const collectAdditionalPublicSecurityFacts: TypeScriptFactDetector = (
  context,
) => {
  const taintedNames = collectRequestDerivedNames(context);
  const functionBindings = resolveFunctionBindings(context);
  const modelNames = collectExpressModelBindings(context);
  const dynamodbClientNames = collectDynamodbClientBindings(context);

  return [
    ...collectHeaderMisuseFacts(context, taintedNames),
    ...collectNosqlInjectionFacts(context, taintedNames, modelNames),
    ...collectDynamodbQueryFacts(context, taintedNames, dynamodbClientNames),
    ...collectFormatStringFacts(context, taintedNames),
    ...collectBrowserOriginFacts(context, functionBindings),
    ...collectModuleLoadFacts(context, taintedNames),
    ...collectHttpResponseFacts(context, taintedNames),
    ...collectHtmlAndWebsocketFacts(context, taintedNames),
    ...collectHardcodedAuthSecretFacts(context),
    ...collectFileAndExceptionFacts(context),
    ...collectFilePermissionFacts(context),
    ...collectObservableTimingFacts(context),
    ...collectRenderAndSendFileFacts(context, taintedNames),
    ...collectDatadogBrowserFacts(context),
    ...collectExpressHardeningFacts(context),
  ];
};
