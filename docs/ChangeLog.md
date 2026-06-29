# v1.0.6

Code review and fixes performed with @CLAUDE_CODE@.
See [ClaudeCodeReview.md](ClaudeCodeReview.md) for the full review. No security
issues were found.

**Bug fixes**

* `cryptoSignOpen()` — output buffer was oversized by `crypto_sign_bytes()` (64)
  bytes, leaving trailing zeros in the returned array. Fixed to allocate exactly
  `sig.length - crypto_sign_bytes()` bytes. Added an early check that throws
  `SodiumLibraryException` when the input is too short to contain a valid signature.
* `cryptoSignOpen()` — on verification failure the method silently returned
  `new byte[1]` instead of throwing `SodiumLibraryException`. Fixed to throw.
* `cryptoSign()` and `cryptoSignOpen()` — the `smlen_p`/`mlen_p` JNA interface
  parameters were declared as `long` instead of `LongByReference`, so the output
  length pointer was never correctly passed to the C side. A leftover debug
  variable `byte[] test` was also removed from `cryptoSign()`. Both fixed.
* `cryptoSignEdSkTOcurveSk()` and `cryptoSignEdPkTOcurvePk()` — both threw
  `"libsodium crypto_generichash failed"` on error, copy-pasted from an unrelated
  method. Error messages now reference the correct C functions.
* `cryptoSecretBoxEasy()` and `cryptoSecretBoxOpenEasy()` — used
  `crypto_box_macbytes()` (public-key box API) to size the MAC instead of
  `crypto_secretbox_macbytes()`. Fixed in both methods.
* Thread safety — the `initialized` flag was not `volatile` and the
  check-then-set was unsynchronized, allowing two threads to call `sodium_init()`
  simultaneously. Fixed with double-checked locking (`volatile` flag +
  `synchronized` block).

**Code quality**

* `log(String)` — body was `System.out.println("MMMM: " + msg)`, bypassing the
  SLF4J logger. Changed to `logger.debug(msg)`.
* `SodiumUtils.hex2Binary()` — swallowed `DecoderException` and returned `null`,
  causing `NullPointerException` at call sites. Now throws
  `IllegalArgumentException` with the original exception as the cause. Removed
  the now-unused `Logger` field and imports.
* `cryptoAuthVerify()` — removed unreachable duplicate `return false`.
* `SodiumLibraryException` — removed redundant private `message` field,
  redundant assignments in constructors, and unnecessary `getMessage()` override.
  `Exception.getMessage()` already returns the correct value.
* Six exception messages had missing spaces between words and numeric values.
  Fixed across `cryptoPwhashArgon2i`, `cryptoPwhashScrypt`,
  `cryptoPwhashScryptSalsa208Sha256`, `cryptoSecretBoxEasy`, `cryptoBoxEasy`,
  and `cryptoBoxOpenEasy`.
* `SingletonHelper` — replaced deprecated `Native.loadLibrary()` with
  `Native.load()` (JNA 5.x).

**API compatibility**

Seven public methods had typos in their names. Correctly-named alias methods
have been added that delegate to the originals. The original methods are marked
`@Deprecated` so existing code compiles unchanged while IDEs guide callers to
the correct names.

| Deprecated | Correct alias |
|---|---|
| `getLibaryPath()` | `getLibraryPath()` |
| `crytoBoxSeedBytes()` | `cryptoBoxSeedBytes()` |
| `crytoBoxPublicKeyBytes()` | `cryptoBoxPublicKeyBytes()` |
| `crytoBoxSecretKeyBytes()` | `cryptoBoxSecretKeyBytes()` |
| `cryptoPwHashMemLimitInterative()` | `cryptoPwHashMemLimitInteractive()` |
| `cryptoSignEdSkTOcurveSk()` | `cryptoSignEdSkToCurveSk()` |
| `cryptoSignEdPkTOcurvePk()` | `cryptoSignEdPkToCurvePk()` |

(Jun-28-2026)

# v1.0.5

* Update JNA version to 5.14.0 from 5.5.0 in order to support Apple silicon. No code change.
  Tested with libsodium 1.0.20

(Aug-31-2024 )

## Update (Feb-02-2026)
* No code change. v1.0.5 is still the stable version.
* Updated main branch with single `pom.xml` to support JDK 8 to JDK 21.  
Previously required separate `pom.xml` (JDK 8) and `pom_java11.xml`
(JDK 11+). `slf4j` deprecated `slf4j-log4j12`, now they created 
`reload4j`. Updated `pom.xml` for that. Use @MARKDOWN_TOC@ to 
generate docs.

## Update (Feb-04-2026)
* Add instructions on how to use from a Gradle project.
* Add gradle test

# v1.0.4

* Support 32 bit Windows.
* Available in maven central.

(Dec-10-2017)

# v1.0.3

* Uses libsodium 1.0.15. libsodium 1.0.15 changed the default password hashing algorithm to Argon2id. Therefore, ```cryptoPwhashArgon2i()``` is updated to use ```crypto_pwhash_alg_argon2id13()```. 

* Test Vectors are created for libsodium 1.0.15

* Merged pull request from https://github.com/bbyrd74 to add support for signing, blake2b generic hash, and key conversion so that ED signing keys can be used for Curve encrypt/decrypt.

* Update pom.xml to bump up version to 1.0.3

(Nov-11-2017)
# v1.0.2
* Update pom.xml, javadoc and documentation for maven central. 
* uses libsodium 1.0.13

# v1.0.1

* Throw SodiumLibraryException in case of error. Before RuntimeException was thrown for everything.

  (Jan-31-2017)

