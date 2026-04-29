import { parse } from '@typescript-eslint/typescript-estree';

import { collectWeakCryptoFacts } from './weak-crypto';

function analyze(text: string) {
  const program = parse(text, {
    comment: true,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectWeakCryptoFacts({
    nodeIds: new WeakMap(),
    path: 'src/example.ts',
    program,
    sourceText: text,
  });
}

describe('collectWeakCryptoFacts', () => {
  it('flags expanded Story 5 crypto hygiene issues', () => {
    const facts = analyze(
      [
        'import argon2 from "argon2";',
        'import { createCipheriv, createHash, generateKeyPairSync, pbkdf2Sync, randomBytes } from "node:crypto";',
        '',
        'const weakDigest = createHash("md5").update("invoice").digest("hex");',
        'const stretchedPassword = pbkdf2Sync(password, salt, 100_000, 32, "sha1");',
        'const weakCipher = createCipheriv("aes-256-ecb", key, iv);',
        'const resetToken = `${Date.now()}-${Math.random().toString(36).slice(2)}`;',
        'const inviteSecret = randomBytes(8).toString("hex");',
        'generateKeyPairSync("rsa", { modulusLength: 1024 });',
        'const sessionToken = createCipheriv("aes-256-cbc", key, Buffer.alloc(16)).update(payload, "utf8", "hex");',
        'argon2.hash(password, { type: argon2.argon2i });',
      ].join('\n'),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.weak-hash-algorithm',
          props: expect.objectContaining({
            algorithm: 'md5',
            sink: 'createHash',
          }),
        }),
        expect.objectContaining({
          kind: 'security.weak-hash-algorithm',
          props: expect.objectContaining({
            algorithm: 'sha1',
            sink: 'pbkdf2Sync',
          }),
        }),
        expect.objectContaining({
          kind: 'security.weak-cipher-or-mode',
          props: expect.objectContaining({
            algorithm: 'aes-256-ecb',
            sink: 'createCipheriv',
          }),
        }),
        expect.objectContaining({
          kind: 'security.predictable-token-generation',
          props: expect.objectContaining({
            target: 'resetToken',
            predictableSources: expect.arrayContaining([
              'Date.now',
              'Math.random',
            ]),
          }),
        }),
        expect.objectContaining({
          kind: 'security.insufficiently-random-values',
          props: expect.objectContaining({
            entropyBytes: 8,
            source: 'randomBytes',
            target: 'inviteSecret',
          }),
        }),
        expect.objectContaining({
          kind: 'security.weak-key-strength',
          props: expect.objectContaining({
            declaredStrength: 1024,
            requiredStrength: 2048,
            sink: 'generateKeyPairSync',
            strengthType: 'modulusLength',
          }),
        }),
        expect.objectContaining({
          kind: 'security.missing-integrity-check',
          props: expect.objectContaining({
            algorithm: 'aes-256-cbc',
            ivIssue: 'fixed',
            sink: 'createCipheriv',
            target: 'sessionToken',
          }),
        }),
        expect.objectContaining({
          kind: 'security.insecure-password-hash-configuration',
          props: expect.objectContaining({
            algorithm: 'argon2.argon2i',
          }),
        }),
      ]),
    );
  });

  it('flags Web Crypto algorithm objects, property writes, and weak symmetric key lengths', () => {
    const facts = analyze(
      [
        'crypto.subtle.digest({ name: "SHA-1" }, payload);',
        'state.invitationToken = `${Date.now()}-${Math.random().toString(36).slice(2)}`;',
        'crypto.subtle.generateKey({ name: "AES-GCM", length: 96 }, true, ["encrypt"]);',
      ].join('\n'),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.weak-hash-algorithm',
          props: expect.objectContaining({
            algorithm: 'SHA-1',
            sink: 'crypto.subtle.digest',
          }),
        }),
        expect.objectContaining({
          kind: 'security.predictable-token-generation',
          props: expect.objectContaining({
            target: 'state.invitationToken',
          }),
        }),
        expect.objectContaining({
          kind: 'security.weak-key-strength',
          props: expect.objectContaining({
            algorithm: 'AES-GCM',
            declaredStrength: 96,
            requiredStrength: 128,
            sink: 'crypto.subtle.generateKey',
          }),
        }),
      ]),
    );
  });

  it('ignores strong hashes, adequate entropy, authenticated encryption, and modern password hashing', () => {
    const facts = analyze(
      [
        'import argon2 from "argon2";',
        'import { createCipheriv, createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";',
        '',
        'const digest = createHash("sha256").update("invoice").digest("hex");',
        'const stretchedPassword = pbkdf2Sync(password, salt, 100_000, 32, "sha256");',
        'const resetToken = randomBytes(32).toString("hex");',
        'createHmac("sha256", macKey).update(payload).digest("hex");',
        'const sessionToken = createCipheriv("aes-256-gcm", key, randomBytes(12)).update(payload, "utf8", "hex");',
        'crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);',
        'argon2.hash(password, { type: argon2.argon2id });',
      ].join('\n'),
    );

    expect(facts).toEqual([]);
  });

  it('suppresses explicit compatibility shims marked by names or nearby comments', () => {
    const facts = analyze(
      [
        'import argon2 from "argon2";',
        'import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";',
        '',
        '// legacy compatibility shim for partner digest interop',
        'export function legacyDigestCompat(payload: string) {',
        '  return createHash("md5").update(payload).digest("hex");',
        '}',
        '',
        'export function compatSessionSecret() {',
        '  return randomBytes(8).toString("hex");',
        '}',
        '',
        'export function migrationInviteToken() {',
        '  return `${Date.now()}-${Math.random().toString(36).slice(2)}`;',
        '}',
        '',
        'export function interopKeyMaterial() {',
        '  return generateKeyPairSync("rsa", { modulusLength: 1024 });',
        '}',
        '',
        'export function compatPasswordHash(password: string) {',
        '  return argon2.hash(password, { type: argon2.argon2i });',
        '}',
      ].join('\n'),
    );

    expect(facts).toEqual([]);
  });
});
