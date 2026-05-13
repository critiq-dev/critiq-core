import {
  collectDynamodbClientBindings,
  collectExpressModelBindings,
  collectRequestDerivedNames,
  collectUploadDerivedNames,
  collectValidatedTrustBoundaryState,
  resolveFunctionBindings,
} from './analysis';
import { collectAngularDomSanitizerFacts } from './angular-dom-sanitizer';
import { collectAjvInsecureConfigurationFacts } from './ajv-insecure-configuration';
import {
  collectDatadogBrowserFacts,
  collectExpressBodyParserLimitsFacts,
  collectExpressHardeningFacts,
  collectHardcodedAuthSecretFacts,
  collectRenderFacts,
} from './application';
import {
  collectExpressErrorHandlerInformationDisclosureFacts,
  collectExpressUserControlledStaticMountFacts,
  collectRequestDrivenArrayIndexFacts,
  collectXmlParseStringWithUntrustedInputFacts,
} from './javascript-security-chunk-b';
import { collectFrameworkConfigSecurityFacts } from './framework-config-security';
import { collectNodeFrameworkBootstrapFacts } from './node-framework-bootstrap';
import { collectDebugStatementInSourceFacts } from './debug-statements';
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
import { collectLogInjectionFacts } from './log-injection';
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
    ...collectLogInjectionFacts(context, taintedNames),
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
    ...collectAngularDomSanitizerFacts(context),
    ...collectExpressHardeningFacts(context, functionBindings),
    ...collectExpressBodyParserLimitsFacts(context, functionBindings),
    ...collectAjvInsecureConfigurationFacts(context),
    ...collectXmlParseStringWithUntrustedInputFacts(context),
    ...collectExpressErrorHandlerInformationDisclosureFacts(context),
    ...collectRequestDrivenArrayIndexFacts(context),
    ...collectExpressUserControlledStaticMountFacts(context),
    ...collectNodeFrameworkBootstrapFacts(context),
    ...collectFrameworkConfigSecurityFacts(context),
    ...collectDebugModeEnabledFacts(context),
    ...collectDebugStatementInSourceFacts(context),
  ];
};
