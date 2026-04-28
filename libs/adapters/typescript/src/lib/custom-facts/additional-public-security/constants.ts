export const FACT_KINDS = {
  datadogBrowserTrackUserInteractions:
    'security.datadog-browser-track-user-interactions',
  dynamodbQueryInjection: 'security.dynamodb-query-injection',
  hardcodedAuthSecret: 'security.hardcoded-auth-secret',
  importUsingUserInput: 'security.import-using-user-input',
  insecureAllowOrigin: 'security.insecure-allow-origin',
  insecureCookie: 'security.express-insecure-cookie',
  insecureCookieHttpOnly: 'security.express-cookie-missing-http-only',
  insecurePasswordHashConfig: 'security.insecure-password-hash-configuration',
  insecureWebsocketTransport: 'security.insecure-websocket-transport',
  jwtNotRevoked: 'security.jwt-not-revoked',
  manualHtmlSanitization: 'security.manual-html-sanitization',
  messageHandlerOriginMissing: 'security.missing-message-origin-check',
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
  expressStaticAssetsAfterSession:
    'security.express-static-assets-after-session',
  expressMissingHelmet: 'security.express-missing-helmet',
  expressReduceFingerprint: 'security.express-reduce-fingerprint',
  unsanitizedHttpResponse: 'security.unsanitized-http-response',
} as const;

export const requestSourcePattern =
  /(?:\b(?:req|request|ctx|context|event)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|\b(?:query|params|body|headers|cookies|payload|session|searchParams|formData)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/u;

export const sensitiveComparePattern =
  /(?:password|passphrase|hash|secret|token|api[_-]?key|auth[_-]?token)/i;

export const sensitiveWritePattern =
  /\b(?:address|auth|card|cookie|credit|dob|email|jwt|pass(word)?|phone|secret|session|ssn|token|user)\b/i;

export const sessionCallNames = new Set(['cookieSession', 'session']);
export const responseSinkNames = new Set(['res.send', 'res.write']);
export const strategyNames = new Set([
  'BearerStrategy',
  'CognitoStrategy',
  'FacebookStrategy',
  'GoogleOauthStrategy',
  'GoogleStrategy',
  'HTTPBearerStrategy',
  'JwtStrategy',
  'LocalStrategy',
  'Strategy',
  'TwitterStrategy',
]);
export const renderSinkNames = new Set(['res.render']);
export const fileWriteSinkNames = new Set([
  'fs.promises.writeFile',
  'fs.writeFile',
  'fs.writeFileSync',
  'writeFile',
  'writeFileSync',
]);
export const sendFileSinkNames = new Set(['res.sendFile']);
export const dynamodbQueryCommandNames = new Set(['QueryCommand']);
