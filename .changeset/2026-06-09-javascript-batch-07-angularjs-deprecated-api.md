---
"@critiq/adapter-typescript": minor
---

Add 8 AngularJS deprecated API fact collectors for JavaScript parity batch 07:

- `collectNoControllerFacts` (`framework.angularjs.discouraged-controller`) — detects `.controller()` calls on AngularJS modules
- `collectNoDeprecatedCookieStoreFacts` (`framework.angularjs.deprecated-cookie-store`) — detects `$cookieStore` references in AngularJS files
- `collectNoDeprecatedDirectiveReplaceFacts` (`framework.angularjs.deprecated-directive-replace`) — detects `replace: true` in directive definition objects
- `collectNoDeprecatedHttpSuccessErrorFacts` (`framework.angularjs.deprecated-http-success-error`) — detects `.success()` / `.error()` on `$http` chains
- `collectInjectFunctionAssignmentsOnlyFacts` (`framework.angularjs.inject-function-should-only-assign`) — detects non-assignment statements in `inject()` callbacks
- `collectPreferAngularForEachFacts` (`framework.angularjs.prefer-angular-for-each`) — detects native `.forEach()` in AngularJS contexts
- `collectNoJqueryWrappingAngularElementFacts` (`framework.angularjs.no-jquery-wrapping-angular-element`) — detects `$(angular.element(...))` wrapping
- `collectPreferAngularIsStringFacts` (`framework.angularjs.prefer-angular-is-string`) — detects `typeof x === "string"` in AngularJS files

All facts are gated by file-level AngularJS context detection to avoid false positives in non-AngularJS code.
