---
"@critiq/adapter-go": minor
"@critiq/adapter-shared": minor
---

Add Go baseline security adapter facts covering listens that bind to all interfaces, imports of the `unsafe` package, `ssh.InsecureIgnoreHostKey()` host-key callbacks, deprecated `ioutil.TempFile`/`ioutil.TempDir` temporary file helpers, `rsa.GenerateKey` and `rsa.GenerateMultiPrimeKey` invocations below 2048 bits, and imports of broken or deprecated `crypto/md5`, `crypto/des`, `crypto/rc4`, and `crypto/sha1` packages.
