export const FACT_KINDS = {
  NO_CONTROLLER: 'framework.angularjs.discouraged-controller',
  NO_DEPRECATED_COOKIE_STORE: 'framework.angularjs.deprecated-cookie-store',
  NO_DEPRECATED_DIRECTIVE_REPLACE: 'framework.angularjs.deprecated-directive-replace',
  NO_DEPRECATED_HTTP_SUCCESS_ERROR: 'framework.angularjs.deprecated-http-success-error',
  INJECT_FUNCTION_ASSIGNMENTS_ONLY: 'framework.angularjs.inject-function-should-only-assign',
  PREFER_ANGULAR_FOR_EACH: 'framework.angularjs.prefer-angular-for-each',
  NO_JQUERY_WRAPPING_ANGULAR_ELEMENT: 'framework.angularjs.no-jquery-wrapping-angular-element',
  PREFER_ANGULAR_IS_STRING: 'framework.angularjs.prefer-angular-is-string',
} as const;
