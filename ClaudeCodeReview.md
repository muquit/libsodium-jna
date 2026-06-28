# Code Review — libsodium-jna

Reviewed by Claude Sonnet 4.6 on 2026-06-28.

---

## Bugs (Functional)

### 1. `cryptoSignOpen()` returns an oversized array ✅ Fixed
**File:** `SodiumLibrary.java`

Output buffer was allocated as `sig.length` bytes, but the actual plaintext is
`sig.length - crypto_sign_bytes()` bytes. The extra trailing bytes remained as
zeros. The JNA interface parameter `mlen_p` was also declared as `long` instead
of `LongByReference`, so the output length pointer was never correctly passed
to the C side.

**Fix:** Corrected buffer size to `sig.length - crypto_sign_bytes()`. Added a
guard that throws `SodiumLibraryException` when the input is too short. Changed
the JNA interface declaration from `long mlen_p` to `LongByReference mlen_p`
and updated the call site accordingly.

---

### 2. `cryptoSignOpen()` silently returns on failure instead of throwing ✅ Fixed
**File:** `SodiumLibrary.java`

On failure the method returned `new byte[1]` despite declaring
`throws SodiumLibraryException`. Every other method in the class throws on
failure.

**Fix:** Replaced the silent `return new byte[1]` with a proper
`throw new SodiumLibraryException(...)`.

---

### 3. `cryptoSign()` passes out-length parameter incorrectly ✅ Fixed
**File:** `SodiumLibrary.java`

The JNA interface declared `smlen_p` as `long`, but in C this is
`unsigned long long *` — an output pointer. The call site passed `test[0]`
(value `0`) via a leftover debug variable `byte[] test = new byte[1]`.

**Fix:** Changed the JNA interface declaration from `long smlen_p` to
`LongByReference smlen_p`. Replaced the `test` debug variable with a proper
`LongByReference smlen` at the call site.

---

### 4. Wrong error messages in ED→Curve key conversion functions ✅ Fixed
**File:** `SodiumLibrary.java`

Both `cryptoSignEdSkTOcurveSk()` and `cryptoSignEdPkTOcurvePk()` threw
`"libsodium crypto_generichash failed"` — copy-pasted from an unrelated method.

**Fix:** Error messages now reference the actual C functions:
`crypto_sign_ed25519_sk_to_curve25519()` and
`crypto_sign_ed25519_pk_to_curve25519()`.

---

### 5. `cryptoPwhashArgon2i` actually uses the Argon2**id** algorithm
**File:** `SodiumLibrary.java`

```java
sodium().crypto_pwhash_alg_argon2id13()  // Argon2id, not Argon2i
```

The method name is `cryptoPwhashArgon2i`, the Javadoc says Argon2i, but the
implementation calls `crypto_pwhash_alg_argon2id13()`. The `deriveKey()` method
delegates to this and inherits the same mismatch. This is a semantic bug:
callers who specifically want Argon2i are silently getting Argon2id.

**Status:** Not fixed — correcting this would silently change the hashing
algorithm for existing callers and break stored hashes.

---

### 6. `cryptoSecretBoxEasy` / `cryptoSecretBoxOpenEasy` query the wrong MAC size function ✅ Fixed
**File:** `SodiumLibrary.java`

Both methods used `crypto_box_macbytes()` (public-key box API) instead of
`crypto_secretbox_macbytes()`. Both return 16 bytes in current libsodium so
there was no runtime failure, but the wrong function was being queried.

**Fix:** Changed to `crypto_secretbox_macbytes()` in both `cryptoSecretBoxEasy`
and `cryptoSecretBoxOpenEasy`.

---

### 7. Thread-safety race condition on the `initialized` flag ✅ Fixed
**File:** `SodiumLibrary.java`

`initialized` was not `volatile` and the check-then-set block was
unsynchronized. Under concurrent access, two threads could both read `false`
and call `sodium_init()` simultaneously.

**Fix:** Applied the double-checked locking pattern — `initialized` is now
`volatile`, and the initialization block is wrapped in
`synchronized (SodiumLibrary.class)` with a second `if (!initialized)` check
inside.

---

## Code Quality / Minor Issues

### 8. Debug `log()` method used `System.out.println` with `"MMMM:"` prefix ✅ Fixed
**File:** `SodiumLibrary.java`

`System.out.println("MMMM: " + msg)` was debug graffiti in a public method,
bypassing the SLF4J logger used everywhere else.

**Fix:** Body replaced with `logger.debug(msg)`.

---

### 9. `SodiumUtils.hex2Binary()` silently returned `null` on error ✅ Fixed
**File:** `SodiumUtils.java`

If hex decoding failed, the method caught `DecoderException`, printed the stack
trace, and returned `null`. No call site checked for null, so a malformed hex
string caused a `NullPointerException` far from the actual failure. The now-
unused `Logger` field and its imports were also left in the class.

**Fix:** The `catch` block now throws `IllegalArgumentException` with the
original `DecoderException` as the cause, giving callers a clear error at the
source. The orphaned `logger` field and `Logger`/`LoggerFactory` imports were
removed.

---

### 10. Missing spaces in exception messages ✅ Fixed
**File:** `SodiumLibrary.java`

Six exception messages had missing spaces between the word `"be"` and the
numeric value, and between the length value and `"bytes"`.

**Fix:** All six messages corrected across `cryptoPwhashArgon2i`,
`cryptoPwhashScrypt`, `cryptoPwhashScryptSalsa208Sha256`, `cryptoSecretBoxEasy`,
`cryptoBoxEasy`, and `cryptoBoxOpenEasy`.

---

### 11. Unreachable duplicate `return false` in `cryptoAuthVerify()` ✅ Fixed
**File:** `SodiumLibrary.java`

```java
if (rc == 0)       { return true;  }
else if (rc == -1) { return false; }
return false;   // dead code
```

The `else if` branch and the trailing `return false` were identical dead code.

**Fix:** Collapsed to a single `if (rc == 0) { return true; } return false;`.

---

### 12. `SodiumLibraryException` had a redundant `message` field ✅ Fixed
**File:** `exceptions/SodiumLibraryException.java`

The class stored `message` in its own private field in addition to calling
`super(message)`, then overrode `getMessage()` to return its own copy.
`Exception.getMessage()` already returns what was passed to `super(message)`,
making the field and the override redundant.

**Fix:** Removed the private `message` field, the redundant assignments in each
constructor, and the `getMessage()` override. The class is now a clean typed
wrapper over `Exception` with identical runtime behaviour.

---

### 13. `Native.loadLibrary()` deprecation warning ✅ Fixed
**File:** `SodiumLibrary.java`

`Native.loadLibrary()` was deprecated in JNA 5.x. Eclipse reported a
deprecation warning on the `SingletonHelper` class.

**Fix:** Replaced `(Sodium) Native.loadLibrary(libPath, Sodium.class)` with
`Native.load(libPath, Sodium.class)` — the modern type-safe equivalent that
requires no cast.

---

## Informational — API Frozen (Typos in Public Method Names)

Correctly-named alias methods have been added that delegate to the original
typo methods. The original methods are marked `@Deprecated` so existing code
continues to compile without errors, while IDEs guide callers toward the
correct names.

| Deprecated (original) | Correct alias added |
|---|---|
| `getLibaryPath()` | `getLibraryPath()` |
| `crytoBoxSeedBytes()` | `cryptoBoxSeedBytes()` |
| `crytoBoxPublicKeyBytes()` | `cryptoBoxPublicKeyBytes()` |
| `crytoBoxSecretKeyBytes()` | `cryptoBoxSecretKeyBytes()` |
| `cryptoPwHashMemLimitInterative()` | `cryptoPwHashMemLimitInteractive()` |
| `cryptoSignEdSkTOcurveSk()` | `cryptoSignEdSkToCurveSk()` |
| `cryptoSignEdPkTOcurvePk()` | `cryptoSignEdPkToCurvePk()` |

---

## Summary

| Category | Total | Fixed | Remaining |
|---|---|---|---|
| Bugs (functional) | 7 | 6 | 1 |
| Code quality / minor | 6 | 6 | 0 |
| Frozen API typos | 7 | 7 (aliases added) | 0 |

The one remaining open item is the `cryptoPwhashArgon2i` / Argon2id algorithm
mismatch (item 5). It cannot be corrected without silently changing the hashing
algorithm for existing callers and invalidating stored password hashes.
