import type { ObservedFact } from '@critiq/core-rules-engine';

import type { TypeScriptFactDetectorContext } from '../shared';
import { collectInjectFunctionAssignmentsOnlyFacts } from './inject-function-assignments-only';
import { collectNoControllerFacts } from './no-controller';
import { collectNoDeprecatedCookieStoreFacts } from './no-deprecated-cookie-store';
import { collectNoDeprecatedDirectiveReplaceFacts } from './no-deprecated-directive-replace';
import { collectNoDeprecatedHttpSuccessErrorFacts } from './no-deprecated-http-success-error';
import { collectNoJqueryWrappingAngularElementFacts } from './no-jquery-wrapping-angular-element';
import { collectPreferAngularForEachFacts } from './prefer-angular-for-each';
import { collectPreferAngularIsStringFacts } from './prefer-angular-is-string';

export function collectAngularJsFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectNoControllerFacts(context),
    ...collectNoDeprecatedCookieStoreFacts(context),
    ...collectNoDeprecatedDirectiveReplaceFacts(context),
    ...collectNoDeprecatedHttpSuccessErrorFacts(context),
    ...collectInjectFunctionAssignmentsOnlyFacts(context),
    ...collectPreferAngularForEachFacts(context),
    ...collectNoJqueryWrappingAngularElementFacts(context),
    ...collectPreferAngularIsStringFacts(context),
  ];
}

export { collectNoControllerFacts } from './no-controller';
export { collectNoDeprecatedCookieStoreFacts } from './no-deprecated-cookie-store';
export { collectNoDeprecatedDirectiveReplaceFacts } from './no-deprecated-directive-replace';
export { collectNoDeprecatedHttpSuccessErrorFacts } from './no-deprecated-http-success-error';
export { collectInjectFunctionAssignmentsOnlyFacts } from './inject-function-assignments-only';
export { collectPreferAngularForEachFacts } from './prefer-angular-for-each';
export { collectNoJqueryWrappingAngularElementFacts } from './no-jquery-wrapping-angular-element';
export { collectPreferAngularIsStringFacts } from './prefer-angular-is-string';
