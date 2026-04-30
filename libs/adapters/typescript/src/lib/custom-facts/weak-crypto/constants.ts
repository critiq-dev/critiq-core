export const WEAK_HASH_RULE_ID = 'security.weak-hash-algorithm';
export const WEAK_CIPHER_RULE_ID = 'ts.security.weak-cipher-or-mode';
export const PREDICTABLE_TOKEN_RULE_ID =
  'ts.security.predictable-token-generation';
export const INSECURE_PASSWORD_HASH_CONFIG_RULE_ID =
  'ts.security.insecure-password-hash-configuration';
export const INSUFFICIENT_RANDOM_RULE_ID =
  'ts.security.insufficiently-random-values';
export const WEAK_KEY_STRENGTH_RULE_ID = 'ts.security.weak-key-strength';
export const MISSING_INTEGRITY_RULE_ID =
  'ts.security.missing-integrity-check';

export const WEAK_HASH_FACT_KIND = 'security.weak-hash-algorithm';
export const WEAK_CIPHER_FACT_KIND = 'security.weak-cipher-or-mode';
export const PREDICTABLE_TOKEN_FACT_KIND = 'security.predictable-token-generation';
export const INSECURE_PASSWORD_HASH_CONFIG_FACT_KIND =
  'security.insecure-password-hash-configuration';
export const INSUFFICIENT_RANDOM_FACT_KIND = 'security.insufficiently-random-values';
export const WEAK_KEY_STRENGTH_FACT_KIND = 'security.weak-key-strength';
export const MISSING_INTEGRITY_FACT_KIND = 'security.missing-integrity-check';

export const weakHashAlgorithmPattern = /^(md4|md5|ripemd160|sha1)$/i;
export const sensitivePasswordValuePattern =
  /(?:password|passphrase|hash|secret|token|api[_-]?key|auth[_-]?token)/i;
export const predictableTokenSourcePattern =
  /(Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now)/i;
export const predictableSourceMatcher =
  /Math\.random|Date\.now|new Date\(\)\.getTime\(\)|performance\.now/gi;

export const compatibilitySensitiveTargetTokens = new Set([
  'api',
  'auth',
  'client',
  'cookie',
  'credential',
  'invite',
  'jwt',
  'magic',
  'nonce',
  'otp',
  'passcode',
  'refresh',
  'reset',
  'secret',
  'session',
  'signing',
  'token',
  'verification',
  'verify',
]);

export const otpLikeTargetTokens = new Set([
  '2fa',
  'code',
  'one',
  'otp',
  'passcode',
  'pin',
  'time',
  'totp',
  'verification',
]);

export const weakHashCallNames = new Set([
  'createHash',
  'createHmac',
  'crypto.createHash',
  'crypto.createHmac',
  'crypto.subtle.digest',
  'globalThis.crypto.subtle.digest',
  'subtle.digest',
]);

export const pbkdf2CallNames = new Set([
  'pbkdf2',
  'pbkdf2Sync',
  'crypto.pbkdf2',
  'crypto.pbkdf2Sync',
]);

export const weakCipherCallNames = new Set([
  'createCipher',
  'createCipheriv',
  'createDecipher',
  'createDecipheriv',
  'crypto.createCipher',
  'crypto.createCipheriv',
  'crypto.createDecipher',
  'crypto.createDecipheriv',
]);

export const rsaPaddingCallNames = new Set([
  'privateDecrypt',
  'privateEncrypt',
  'publicDecrypt',
  'publicEncrypt',
  'crypto.privateDecrypt',
  'crypto.privateEncrypt',
  'crypto.publicDecrypt',
  'crypto.publicEncrypt',
]);

export const rsaKeyGenerationCallNames = new Set([
  'generateKeyPair',
  'generateKeyPairSync',
  'crypto.generateKeyPair',
  'crypto.generateKeyPairSync',
]);

export const symmetricKeyGenerationCallNames = new Set([
  'generateKey',
  'generateKeySync',
  'crypto.generateKey',
  'crypto.generateKeySync',
]);

export const webCryptoGenerateKeyCallNames = new Set([
  'crypto.subtle.generateKey',
  'globalThis.crypto.subtle.generateKey',
  'subtle.generateKey',
]);

export const integrityHelperCallNames = new Set([
  'createHmac',
  'crypto.createHmac',
  'crypto.subtle.sign',
  'globalThis.crypto.subtle.sign',
  'subtle.sign',
]);
