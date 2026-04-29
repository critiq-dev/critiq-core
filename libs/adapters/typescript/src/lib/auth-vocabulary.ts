const authLikeNameTokens = new Set([
  'access',
  'auth',
  'authentication',
  'authorization',
  'bearer',
  'cookie',
  'cookies',
  'credential',
  'credentials',
  'identity',
  'jwt',
  'nonce',
  'refresh',
  'secret',
  'session',
  'sid',
  'token',
]);

const personallySensitiveNameTokens = new Set([
  'address',
  'card',
  'credit',
  'cvv',
  'dob',
  'email',
  'passcode',
  'password',
  'phone',
  'ssn',
]);

const privilegedIdentityFieldTokens = new Set([
  'admin',
  'billing',
  'entitlement',
  'entitlements',
  'feature',
  'featureflag',
  'featureflags',
  'flag',
  'flags',
  'group',
  'groups',
  'isadmin',
  'owner',
  'ownerid',
  'owners',
  'permission',
  'permissions',
  'privilege',
  'privileges',
  'role',
  'roles',
  'scope',
  'scopes',
  'tenant',
  'tenantid',
]);

const jwtClaimSensitiveTokens = new Set([
  ...authLikeNameTokens,
  ...personallySensitiveNameTokens,
  ...privilegedIdentityFieldTokens,
  'profile',
  'support',
  'user',
  'userid',
]);

const authCookieNameTokens = new Set([
  'access',
  'auth',
  'id',
  'identity',
  'jwt',
  'refresh',
  'session',
  'sid',
  'token',
]);

const authStorageKeyTokens = new Set([
  'access',
  'auth',
  'bearer',
  'credential',
  'credentials',
  'id',
  'identity',
  'jwt',
  'refresh',
  'session',
  'sid',
  'token',
]);

const authSecretPropertyNames = new Set([
  'clientsecret',
  'consumersecret',
  'cookiekey',
  'cookiekeys',
  'jwtsecret',
  'key',
  'keys',
  'secret',
  'secretkey',
  'secretorkey',
  'sessionsecret',
  'signingkey',
  'signingsecret',
]);

export const authTokenLikeNameTokens = new Set([
  'auth',
  'authorization',
  'cookie',
  'jwt',
  'session',
  'token',
]);

export const authSessionCallNames = new Set(['cookieSession', 'session']);

export const authStrategyNames = new Set([
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

export function tokenizeIdentifierLikeText(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+|\s+/)
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token.length > 0);
}

function hasToken(
  text: string | undefined,
  tokens: ReadonlySet<string>,
): boolean {
  if (!text) {
    return false;
  }

  return tokenizeIdentifierLikeText(text).some((token) => tokens.has(token));
}

function normalizedIdentifierName(text: string | undefined): string {
  if (!text) {
    return '';
  }

  return tokenizeIdentifierLikeText(text).join('');
}

export function isAuthLikeText(text: string | undefined): boolean {
  return hasToken(text, authLikeNameTokens);
}

export function isPrivilegedIdentityFieldText(
  text: string | undefined,
): boolean {
  return hasToken(text, privilegedIdentityFieldTokens);
}

export function isSensitiveAuthJwtClaimText(
  text: string | undefined,
): boolean {
  return hasToken(text, jwtClaimSensitiveTokens);
}

export function isAuthCookieName(text: string | undefined): boolean {
  return hasToken(text, authCookieNameTokens);
}

export function isAuthStorageKey(text: string | undefined): boolean {
  return hasToken(text, authStorageKeyTokens);
}

export function isSensitiveIdentifierText(text: string | undefined): boolean {
  return (
    hasToken(text, authLikeNameTokens) ||
    hasToken(text, personallySensitiveNameTokens) ||
    hasToken(text, privilegedIdentityFieldTokens)
  );
}

export function isAuthSecretPropertyName(text: string | undefined): boolean {
  const normalized = normalizedIdentifierName(text);

  return normalized.length > 0 && authSecretPropertyNames.has(normalized);
}
