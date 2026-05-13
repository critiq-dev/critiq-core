import {
  authSessionCallNames,
  authStrategyNames,
} from '../../auth-vocabulary';
import {
  trustBoundaryRequestSourcePattern,
  trustBoundaryViewRenderSinkCallees,
} from '../../trust-boundary';

export const FACT_KINDS = {
  datadogBrowserTrackUserInteractions:
    'security.datadog-browser-track-user-interactions',
  dangerousInsertHtml: 'security.dangerous-insert-html',
  dangerouslySetInnerHtml: 'security.dangerously-set-inner-html',
  dynamodbQueryInjection: 'security.dynamodb-query-injection',
  externalFileUpload: 'security.external-file-upload',
  hardcodedAuthSecret: 'security.hardcoded-auth-secret',
  handlebarsNoEscape: 'security.handlebars-no-escape',
  fileGeneration: 'security.file-generation',
  importUsingUserInput: 'security.import-using-user-input',
  insecureAllowOrigin: 'security.insecure-allow-origin',
  permissiveAllowOrigin: 'security.permissive-allow-origin',
  insecureCookie: 'security.express-insecure-cookie',
  insecureCookieHttpOnly: 'security.express-cookie-missing-http-only',
  insecurePasswordHashConfig: 'security.insecure-password-hash-configuration',
  insecureWebsocketTransport: 'security.insecure-websocket-transport',
  jwtNotRevoked: 'security.jwt-not-revoked',
  manualHtmlSanitization: 'security.manual-html-sanitization',
  messageHandlerOriginMissing: 'security.missing-message-origin-check',
  nonLiteralFsFilename: 'security.non-literal-fs-filename',
  noInnerHtmlAssignment: 'security.no-innerhtml-assignment',
  nosqlInjection: 'security.express-nosql-injection',
  observableTimingDiscrepancy: 'security.observable-timing-discrepancy',
  permissiveFilePermissions: 'security.permissive-file-permissions',
  postMessageWildcardOrigin: 'security.postmessage-wildcard-origin',
  rawHtmlUsingUserInput: 'security.raw-html-using-user-input',
  sensitiveDataInException: 'security.sensitive-data-in-exception',
  sensitiveDataWrittenToFile: 'security.sensitive-data-written-to-file',
  uiRedress: 'security.ui-redress',
  untrustedFormatString: 'security.format-string-using-user-input',
  userControlledSendFile: 'security.user-controlled-sendfile',
  userControlledViewRender: 'security.user-controlled-view-render',
  exposedDirectoryListing: 'security.exposed-directory-listing',
  expressDefaultSessionConfig: 'security.express-default-session-config',
  expressDefaultCookieConfig: 'security.express-default-cookie-config',
  expressPermissiveCookieConfig:
    'security.express-permissive-cookie-config',
  expressStaticAssetsAfterSession:
    'security.express-static-assets-after-session',
  expressMissingHelmet: 'security.express-missing-helmet',
  expressReduceFingerprint: 'security.express-reduce-fingerprint',
  expressUnboundedBodyParser: 'security.express-unbounded-body-parser',
  fastifyExcessiveBodyLimit: 'security.fastify-excessive-body-limit',
  fastifyPublicBindWithoutTrustProxy:
    'security.fastify-public-bind-without-trust-proxy',
  apolloServerCsrfDisabled: 'security.apollo-server-csrf-disabled',
  apolloServerGraphqlDevToolingExposure:
    'security.apollo-server-graphql-dev-tooling-exposure',
  graphqlUploadWithoutCsrfGuard: 'security.graphql-upload-without-csrf-guard',
  nuxtPublicRuntimeSecret: 'security.nuxt-public-runtime-secret',
  astroVitePublicSecretDefine: 'security.astro-vite-public-secret-define',
  apolloServerIntrospectionExposure: 'security.apollo-server-introspection-exposure',
  apolloServerMissingQueryLimits: 'security.apollo-server-missing-query-limits',
  nestjsHelmetAfterRouteMount: 'security.nestjs-helmet-after-route-mount',
  nestjsMissingGlobalValidationPipe: 'security.nestjs-missing-global-validation-pipe',
  nestjsValidationPipeWithoutWhitelist: 'security.nestjs-validation-pipe-without-whitelist',
  nestjsSkipThrottleSensitiveRoute: 'security.nestjs-skip-throttle-sensitive-route',
  angularDomSanitizerBypassUntrustedInput:
    'security.angular-dom-sanitizer-bypass-untrusted-input',
  nextServerActionMissingLocalAuth:
    'security.next-server-action-missing-local-auth',
  informationLeakage: 'security.information-leakage',
  debugModeEnabled: 'security.debug-mode-enabled',
  unsanitizedHttpResponse: 'security.unsanitized-http-response',
  logInjection: 'security.log-injection',
  debugStatementInSource: 'security.debug-statement-in-source',
  insecureHelmetHardeningOptions: 'security.insecure-helmet-hardening-options',
  expressStaticDotfilesAllow: 'security.express-static-dotfiles-allow',
  insecureContentSecurityPolicyLiteral:
    'security.insecure-content-security-policy-literal',
  ajvInsecureConfiguration: 'security.ajv-insecure-configuration',
  xmlParseStringWithUntrustedInput: 'security.xml-parse-string-with-untrusted-input',
  expressErrorHandlerInformationDisclosure:
    'security.express-error-handler-information-disclosure',
  requestDrivenArrayIndexAccess: 'security.request-driven-array-index-access',
  expressUserControlledStaticMount:
    'security.express-user-controlled-static-mount',
  electronShellOpenExternalUnvalidated:
    'security.electron-shell-open-external-unvalidated',
  iframeMissingSandboxAttribute: 'security.iframe-missing-sandbox-attribute',
} as const;

export const requestSourcePattern = trustBoundaryRequestSourcePattern;

export const sensitiveComparePattern =
  /(?:password|passphrase|hash|secret|token|api[_-]?key|auth[_-]?token)/i;

export const sessionCallNames = authSessionCallNames;
export const responseSinkNames = new Set(['res.end', 'res.send', 'res.write']);
export const strategyNames = authStrategyNames;
export const renderSinkNames = trustBoundaryViewRenderSinkCallees;
export const fileReadSinkNames = new Set([
  'createReadStream',
  'fs.createReadStream',
  'fs.promises.readFile',
  'fs.readFile',
  'fs.readFileSync',
  'readFile',
  'readFileSync',
]);
export const fileWriteSinkNames = new Set([
  'appendFile',
  'appendFileSync',
  'createWriteStream',
  'fs.appendFile',
  'fs.appendFileSync',
  'fs.createWriteStream',
  'fs.promises.appendFile',
  'fs.promises.writeFile',
  'fs.writeFile',
  'fs.writeFileSync',
  'writeFile',
  'writeFileSync',
]);
export const permissionOptionSinkNames = new Set([
  'appendFile',
  'appendFileSync',
  'createWriteStream',
  'fs.appendFile',
  'fs.appendFileSync',
  'fs.createWriteStream',
  'fs.mkdir',
  'fs.mkdirSync',
  'fs.promises.appendFile',
  'fs.promises.mkdir',
  'fs.promises.writeFile',
  'fs.writeFile',
  'fs.writeFileSync',
  'mkdir',
  'mkdirSync',
  'writeFile',
  'writeFileSync',
]);
export const sendFileSinkNames = new Set(['res.sendFile']);
export const dynamodbQueryCommandNames = new Set([
  'QueryCommand',
  'ScanCommand',
]);
