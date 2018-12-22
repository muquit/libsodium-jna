## Generate random data

```java
/**
 * Return unpredictable sequence of bytes.
 *
 * Excerpt from libsodium documentation:
 * 
 *  - On Windows systems, the RtlGenRandom() function is used
 *  - On OpenBSD and Bitrig, the arc4random() function is used
 *  - On recent Linux kernels, the getrandom system call is used (since Sodium 1.0.3)
 *  - On other Unices, the /dev/urandom device is used
 *  - If none of these options can safely be used, custom implementations can easily be hooked.
 *
 * Parameters:
 *   size Number of random bytes to generate
 *
 * Return:
 *   Array of random bytes
 */
 public static byte[] randomBytes(int size)
```

### Example: Generate random data

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

```java
// generate 16 bytes of random data
byte[] randomBytes = SodiumLibrary.randomBytes(16);
String hex = SodiumUtils.binary2Hex(salt);

// generate libsodium's standard number of salt bytes
int n = SodiumLibrary.cryptoNumberSaltBytes();
logger.info("Generate " + n + " random bytes");
byte[] salt = SodiumLibrary.randomBytes(n);
logger.info("Generated " + salt.length + " random bytes");
String hex = SodiumUtils.binary2Hex(salt);
logger.info("Random bytes: " + hex);
```

