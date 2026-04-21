import { parse } from '@typescript-eslint/typescript-estree';

import {
  collectWeakCryptoFacts,
} from './weak-crypto';

function analyze(text: string) {
  const program = parse(text, {
    comment: false,
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
  it('flags weak hash, weak cipher, and predictable token generation', () => {
    const facts = analyze(
      [
        'import { createHash, createCipheriv } from "node:crypto";',
        '',
        'const weakDigest = createHash("md5").update("invoice").digest("hex");',
        'const weakCipher = createCipheriv("aes-256-ecb", key, iv);',
        'const resetToken = `${Date.now()}-${Math.random().toString(36).slice(2)}`;',
      ].join('\n'),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.weak-hash-algorithm',
          appliesTo: 'block',
          props: expect.objectContaining({
            algorithm: 'md5',
            sink: 'createHash',
          }),
        }),
        expect.objectContaining({
          kind: 'security.weak-cipher-or-mode',
          appliesTo: 'block',
          props: expect.objectContaining({
            algorithm: 'aes-256-ecb',
            sink: 'createCipheriv',
          }),
        }),
        expect.objectContaining({
          kind: 'security.predictable-token-generation',
          appliesTo: 'block',
          props: expect.objectContaining({
            target: 'resetToken',
          }),
        }),
      ]),
    );

    expect(facts).toHaveLength(3);
  });

  it('ignores strong hashes, safe ciphers, and crypto-backed tokens', () => {
    const facts = analyze(
      [
        'import { createHash, createCipheriv, randomBytes } from "node:crypto";',
        '',
        'const digest = createHash("sha256").update("invoice").digest("hex");',
        'const cipher = createCipheriv("aes-256-gcm", key, iv);',
        'const resetToken = randomBytes(32).toString("hex");',
      ].join('\n'),
    );

    expect(facts).toEqual([]);
  });

  it('flags predictable token generation returned directly from token-like helpers', () => {
    const facts = analyze(
      [
        'export function buildSessionToken(userId: string): string {',
        '  return `${Date.now()}-${Math.random().toString(36).slice(2)}-${userId}`;',
        '}',
      ].join('\n'),
    );

    expect(facts).toEqual([
      expect.objectContaining({
        kind: 'security.predictable-token-generation',
        appliesTo: 'block',
        props: expect.objectContaining({
          target: 'buildSessionToken',
          predictableSources: expect.arrayContaining(['Date.now', 'Math.random']),
        }),
      }),
    ]);
  });
});
