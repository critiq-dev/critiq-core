export const SENSITIVE_LABEL_PATTERN =
  /\b(address|auth|body|card|cookie|credit|dob|email|jwt|pass(word)?|payload|phone|secret|session|ssn|token)\b/i;
export const CREDENTIAL_IDENTIFIER_PATTERN =
  /(password|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)/i;
export const REDACTION_WRAPPER_PATTERN =
  /\b(redact|mask|sanitize|anonymize|drop_sensitive|dropSensitive|omit_sensitive|omitSensitive|hash_sensitive|hashSensitive|safe_serialize|safeSerialize)\b/i;
