## Password hashing, key generation

From [libsodium documentation](https://download.libsodium.org/doc/password_hashing/):

> Password hashing functions derive a secret key of any size from a password and a salt.

* The generated key has the size defined by the application, no matter what the password length is.
* The same password hashed with same parameters will always produce the same output.
* The same password hashed with different salts will produce different outputs.
* The function deriving a key from a password and a salt is CPU intensive and intentionally requires a fair amount of memory. Therefore, it mitigates brute-force attacks by requiring a significant effort to verify each password.


### Derive Key from password

```java
/**
 * Derives a key from a password and the given salt using Argon2i 
 *
 * Parameters:
 *  password    The password
 *  salt        The salt. The salt must be SodiumLibrary.cryptoPwhashSaltBytes() bytes long
 *
 * Comments:
 *  This method uses:
 *   opslimit as crypto_pwhash_opslimit_interactive()
 *   memlimit as crypto_pwhash_memlimit_interactive()
 *   algorithm as crypto_pwhash_alg_argon2id13() (default n libsodium v1.0.15)
 *
 * Returns:
 *  The derived key as array of bytes. 
 * In case of error SodiumLibraryException() run time exception will be thrown 
 */
public static byte[] cryptoPwhashArgon2i(byte[] passwd, byte[] salt) throws SodiumLibraryException
```

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

### Example: Derive key from password

```
  String passPhrase = "This is a passphrase";
  byte[] salt = SodiumLibrary.randomBytes(SodiumLibrary.cryptoPwhashSaltBytes());
  String hex = SodiumUtils.binary2Hex(salt);

  // create salt for deriving key from the pass phrase
  // salt is public but needs to be saved
  logger.info("Generated " + salt.length + " bytes of salt");
  logger.info(hex);
  logger.info("Derive key from passphrase");
  byte[] key = SodiumLibrary.cryptoPwhashArgon2i(passPhrase.getBytes(), salt);
  logger.info("Derived " + key.length + " bytes long key");
  hex = SodiumUtils.binary2Hex(key);
  logger.info(hex);

  // Later when you need to derive the key from the passphrase, use the saved salt 
```

### Derive US-ASCII encoded key from password for storing

```java
/**
 * Returns a US-ASCII encoded key derived from the password. The key can be stored for 
 * verification. 
 *
 * Parameters:
 *  password  The password
 *
 * Comments:
 *  Memory-hard, CPU-intensive hash function is applied to the
 *  password in key generation process.
 *
 *  Automatically generated salt is used in the key generation
 *
 *  Uses opslimit as crypto_pwhash_opslimit_interactive()
 *  Uses memlimit as crypto_pwhash_memlimit_interactive()
 *  
 * Returns:
 *  derived key as US-ASCII encoded string
 */
public static String cryptoPwhashStr(byte[] password) throws SodiumLibraryException
```

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

### Example: Dervice key from password as US-ASCII string

```
    String password = new String("বাংলা");
		// convert to UTF-8 encoded bytes
		byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8); // requires jdk 1.7+
		String key = SodiumLibrary.cryptoPwhashStr(passwordBytes);
```

### Verify Stored US-ASCII encoded key with password

```java
/**
 * Verify a US-ASCII encoded key derived previously by calling 
 * cryptoPwhashStr()
 *
 * Parameters:
 *  key         US-ASCII encoded key to verify
 *  password    The password
 *
 * Returns:
 *  true if the key can be verified, false otherwise
 */
 public static boolean cryptoPwhashStrVerify(String usAsciiKey, 
    byte[] password)
```

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

### Example: Verify US-ASCII encoded string
```java
String password = new String("বাংলা");
// convert to UTF-8 encoded bytes
byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8); // requires jdk 1.7+
String key = SodiumLibrary.cryptoPwhashStr(passwordBytes);
// verify the password
boolean rc = SodiumLibrary.cryptoPwhashStrVerify(key, passwordBytes);
if (rc)
{
    logger.info("Password is verified");
}
```

