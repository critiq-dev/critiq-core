import { collectPythonWeakHashFacts } from './python-weak-hash-algorithm';

describe('python-weak-hash-algorithm collectors', () => {
  const detector = 'python-detector';

  it('flags weak digests in session and signing contexts', () => {
    const facts = collectPythonWeakHashFacts({
      detector,
      text: [
        'import hashlib',
        'import hmac',
        '',
        'def sign_session(payload: bytes, secret: bytes):',
        '    return hashlib.sha1(payload + secret).hexdigest()',
        '',
        'def sign_hmac(payload: bytes, secret: bytes):',
        '    return hmac.new(secret, payload, digestmod=hashlib.sha1).hexdigest()',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'security.weak-hash-algorithm'),
    ).toHaveLength(2);
  });

  it('suppresses checksum-only digest helpers', () => {
    const facts = collectPythonWeakHashFacts({
      detector,
      text: [
        'import hashlib',
        '',
        'def checksum(payload: bytes):',
        '    return hashlib.md5(payload).hexdigest()',
        '',
        '# critiq:compat legacy etag helper',
        'def etag(value: bytes):',
        '    return hashlib.sha1(value).hexdigest()',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'security.weak-hash-algorithm'),
    ).toHaveLength(0);
  });
});
