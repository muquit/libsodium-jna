<!-- TOC -->

- [Introduction](#introduction)
- [Supported platforms](#supported-platforms)
- [Requirements](#requirements)
- [How to use](#how-to-use)
    - [Install native libsodium C library  first](#install-native-libsodium-c-library--first)
    - [Install ```libsodium-jna```](#install-libsodium-jna)
    - [Update your project's ```pom.xml```](#update-your-projects-pomxml)
- [Supported APIs](#supported-apis)
    - [Version of sodium library](#version-of-sodium-library)
    - [Generating random data](#generating-random-data)
    - [Secret-key cryptography](#secret-key-cryptography)
    - [Public-key cryptography](#public-key-cryptography)
    - [Password hashing, Key generation](#password-hashing-key-generation)
- [APIs](#apis)
    - [Load the libsodium C Library first](#load-the-libsodium-c-library-first)
        - [Example: Load the native libsodium library](#example-load-the-native-libsodium-library)
    - [Version of sodium library](#version-of-sodium-library-1)
        - [Example: Print libsodium version](#example-print-libsodium-version)
    - [Generate random data](#generate-random-data)
        - [Example: Generate random data](#example-generate-random-data)
    - [Secret-key authenticated cryptography](#secret-key-authenticated-cryptography)
        - [Encrypt a message with a key and a nonce](#encrypt-a-message-with-a-key-and-a-nonce)
        - [Verify and decrypt the message](#verify-and-decrypt-the-message)
        - [Example: Encrypt and Decrypt a message](#example-encrypt-and-decrypt-a-message)
    - [Public-key cryptography](#public-key-cryptography-1)
        - [Generate Key Pair](#generate-key-pair)
        - [Example: Generate key pair](#example-generate-key-pair)
        - [Example: Alice shares secret with Bob, Bob verifies and decrypt it](#example-alice-shares-secret-with-bob-bob-verifies-and-decrypt-it)
        - [Example: Alice (sender) anonymously encrypts message with Bob's (recipient) public key](#example-alice-sender-anonymously-encrypts-message-with-bobs-recipient-public-key)
        - [Example: Bob (recipient) decrypts the message with his private key](#example-bob-recipient-decrypts-the-message-with-his-private-key)
    - [Password hashing, key generation](#password-hashing-key-generation)
        - [Derive Key from password](#derive-key-from-password)
        - [Example: Derive key from password](#example-derive-key-from-password)
        - [Derive US-ASCII encoded key from password for storing](#derive-us-ascii-encoded-key-from-password-for-storing)
        - [Example: Dervice key from password as US-ASCII string](#example-dervice-key-from-password-as-us-ascii-string)
        - [Verify Stored US-ASCII encoded key with password](#verify-stored-us-ascii-encoded-key-with-password)
        - [Example: Verify US-ASCII encoded string](#example-verify-us-ascii-encoded-string)
    - [How to encrypt a private key](#how-to-encrypt-a-private-key)
        - [Encrypting the private key](#encrypting-the-private-key)
        - [Decrypting the private key](#decrypting-the-private-key)
- [If your project is not a maven project](#if-your-project-is-not-a-maven-project)
- [License is MIT](#license-is-mit)

<!-- /TOC -->

# Introduction

*libsodium-jna* is a java library that binds to [libsodium](https://libsodium.org) C crypto APIs with [Java Native Access](https://github.com/java-native-access/jna) (JNA). I wrote it because I did not like any of the Java implementation of libsodium. I hope you will find this project useful and fun to use. 

Bug reports, suggestions are always welcome! 

If you add support to more libsodium APIs, please send me a pull request. If yo do so, please do not forget to update the documentation add unit tests. If you need to generate test vectors, please look at ```misc/gen_test_vectors.c```

# Supported platforms

In theory it should work on any platform where native libsodium library works and JVM 1.7+ is available. 

The implementation is tested on the following platforms with libsodium v1.0.13 with JVM 1.7 and 1.8.

| Platform | JVM |
|----------|-----|
| 64 bit Windows 7 and 10 | 64 bit JVM |
| 64 bit MacOS X running Sierra and El Capitan | 64 bit JVM |
| 64 bit Linux | 64 bit JVM |
| 32 bit Linux | 32 bit JVM |

# Requirements

* jdk 1.7+

* maven must be installed in order to create the jar file. However, it is possible to use the library in a 
non-maven project.

* [libsodium](https://libsodium.org) 1.0.11 or higher. libsodium-jna itself does not enforce version checking but make sure you are using libsodium v 1.0.11 or higher.

* Make sure native [libsodium](https://libsodium.org) is already installed in the system. This library does not come with native version of libsodium. *It is a good idea to compile and install [libsodium](https://libsodium.org) yourself instead of using one from the Internet*.

* This library does not load any libsodium library from path, rather you have to specify exactly where the library is located. 

# How to use
## Install native libsodium C library  first

* Compile and Install libsodium. It is a requirement.
  * Download [libsodium-1.0.13.tar.gz](https://download.libsodium.org/libsodium/releases/)
  * make sure ```pkg-config``` is installed
  
Follow the instructions on [libsodium doc](https://download.libsodium.org/doc/) page on how to compile and install. I do the following on Linux and Mac OS X:

```
  tar -xf libsodium-1.0.13.tar.gz
  cd libsodium-1.0.13
  ./configure
  make && make check
  sudo make install
  sudo ldconfig
```

## Install ```libsodium-jna```

At this time, *libsodium-jna* is not in maven central. Therefore, before using it, it must be installed first.

```
    git clone https://github.com/muquit/libsodium-jna.git
    cd libsodium-jna
    mvn clean install
    mvn test
```

To load the project in Eclipse, select _File->Import...->Maven->Existing Maven Projects_, then Click on *Next >*, click on *Browse...* button and select the libsodium-jna directory.

## Update your project's ```pom.xml```

Add the following block inside dependencies block:

```
    <!-- 
     | libsodium-jna is not in the maven central yet (I am working on it). 
     | So it has to be installed first at the system by typing: mvn clean install
     | and most of all native libsodium must be installed first in the 
     | system before using it.
    -->
    <dependency>
        <groupId>com.muquit.libsodiumjna</groupId>
        <artifactId>libsodium-jna</artifactId>
        <version>1.0.2</version>
    </dependency>
```
Note: If you do not use maven, look at the end of the document.

# Supported APIs

Before making any API calls, native sodium must be loaded from a specific path. Please look at the section [Load the libsodium C Library first](#load-the-libsodium-c-library-first) for details. 

The following APIs are implemented at this time.

## Version of sodium library

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|```sodium_version_string()```|```libsodiumVersionString()```|Return the version of native sodium library|

## Generating random data

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|```randombytes_buf()```|```randomBytes()```|Reruns specified number of unpredictable sequence of bytes|

## Secret-key cryptography

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|[```crypto_secretbox_easy()```](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html)| ```public static byte[] cryptoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key)``` |Encrypts a message with a key and a nonce|
|[```crypto_secretbox_open_easy()```](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html)|```public static byte[] cryptoSecretBoxOpenEasy(byte[] cipherText,byte[] nonce, byte[] key)```|Verifies and decrypts an encrypted message produced by ```cryptoSecretBoxEasy()```|
|```crypto_secretbox_detached()```|```public static SodiumSecretBox cryptoSecretBoxDetached(byte[] message, byte[] nonce, byte[] key)```|Encrypts a message with a key and a nonce and returns authentication tag with the encrypted message|
|```crypto_secretbox_open_detached()```|```public static byte[] cryptoSecretBoxOpenDetached(SodiumSecretBox secretBox, byte[] nonce, byte[] key)```|Verifies and decrypts an encrypted message, authentication tag used in ```cryptoSecretBoxDetached()``` is needed|
|```crypto_auth()```|```public static byte[] cryptoAuth(byte[] message, byte[] key)```|Computes an authentication tag for a message | 
|```crypto_auth_verify()```|```public static boolean cryptoAuthVerify(byte[] mac, byte[] message, byte[] key)```|Verifies the authentication tag for a message|
|```crypto_secretbox_keybytes()```|```public static long cryptoSecretBoxKeyBytes()```|Length of key|
|```crypto_secretbox_noncebytes()```|```public static long cryptoSecretBoxNonceBytes()```|Length of nonce|
|```crypto_secretbox_macbytes()```|```public static long cryptoSecretBoxMacBytes()```|Length of authentication code|

## Public-key cryptography

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|[```crypto_box_keypair()```](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html)|[```public static SodiumKeyPair cryptoBoxKeyPair()```](#generate-key-pair)|Randomly generate a private key and a corresponding public key |
|```crypto_scalarmult_base()```|```public static byte[] cryptoPublicKey(byte[] privateKey)```|Compute public key given a private key|
|```crypto_box_easy()```|```public static byte[] cryptoBoxEasy(byte[] message, byte[] nonce, byte[] publicKey, byte[] privateKey)```|Encrypts a message with a recipient's public key, sender's private key and a nonce|
|```crypto_box_open_easy()```|```public static byte[] cryptoBoxOpenEasy(byte[] cipherText, byte[]nonce, byte[] publicKey, byte[] privateKey)```|Verifies and decrypts an encrypted message produced by ```cryptoBoxEasy()```|
|```crypto_box_seal()```|```public static byte[] cryptoBoxSeal(byte[] message, byte[] recipientPublicKey)```|Encrypts a message for a recipient with recipient's public key|
|```crypto_box_seal_open()```|```public static byte[] cryptoBoxSealOpen(byte[] cipherText,byte[] pk, byte[] sk)```|Decrypts an encrypted message with the key pair public key and private key|
|```crypto_box_noncebytes()```|```public static long cryptoBoxNonceBytes()```|Length of nonce|
|```crypto_box_seedbytes()```| ```public static long crytoBoxSeedBytes()```|Length of key seed|
|```crypto_box_publickeybytes()```|```public static long crytoBoxPublicKeyBytes()```|Length of public key|
|```crypto_box_secretkeybytes()```|```public static long crytoBoxSecretKeyBytes()```|Length of private key|
|```crypto_box_macbytes()```|```public static long cryptoBoxMacBytes()```|Length of mac|
|```crypto_box_sealbytes()```|```public static long cryptoBoxSealBytes()```|Length of seal|

## Password hashing, Key generation

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|[```crypto_pwhash()```](https://download.libsodium.org/doc/password_hashing/the_argon2i_function.html)| ```public static byte[] cryptoPwhash(byte[] passwd, byte[] salt, long opsLimit, NativeLong memLimit, int algorithm)```|Derives a key from a password. The ```salt```, ```opslimit```, ```memlimit``` and ```algorithm``` can be specified.
|                      | ```public static byte[] cryptoPwhashArgon2i(byte[] passwd, byte[] salt)``` |Derives a key from a password using Argon2 memory-hard function. Uses default values for opsLimit and memLimit|
|                      | ```public static byte[] cryptoPwhashScrypt(byte[] passwd, byte[] salt)``` |Derives a key from a password using Scrypt|
|```crypto_pwhash_str()```|```public static String cryptoPwhashStr(byte[] password)```|Derives a US ASCII encoded key from a password using  memory-hard, CPU-intensive hash function|
|```cryupto_pwhash_str_verify()```|```public static boolean cryptoPwhashStrVerify(String usAsciiKey, byte[] password)```|Verifies a US ASCII encoded password string generated by ```cryptoPwhashStr()```|
|```crypto_pwhash_scryptsalsa208sha256()```|```public static byte[] cryptoPwhashScryptSalsa208Sha256(byte[] key, byte[] passwd, byte[] salt, long opslimit, NativeLong memlimit)```|
|```crypto_pwhash_alg_argon2i13()```|```public static int cryptoPwhashAlgArgon2i13()```|-|
|```crypto_pwhash_alg_default()```|```public static int cryptoPwhashAlgDefault()```|-|
|```crypto_pwhash_saltbytes()```|```public static int cryptoNumberSaltBytes()```|Length of salt|
|```crypto_pwhash_saltbytes()```|```public static int cryptoPwhashSaltBytes()```|Length of salt|
|```crypto_pwhash_opslimit_interactive()```|```public static long cryptoPwHashOpsLimitInteractive()```|-|
|```crypto_pwhash_memlimit_interactive()```|```public static NativeLong cryptoPwHashMemLimitInterative()```|-|
|```crypto_pwhash_scryptsalsa208sha256_saltbytes()```|```public static long cryptoPwHashScryptSalsa208Sha256SaltBytes()```|-|

# APIs

## Load the libsodium C Library first

Before making call to any API, the native *sodium C library*  must be loaded explicitly from a specific path. It is possible to load the library
from path, however *libsodium-jna* is designed to load *sodium library* explicitly from a path.

### Example: Load the native libsodium library

```java
private static String libraryPath = null;

if (Platform.isMac())
{
    // MacOS
    libraryPath = "/usr/local/lib/libsodium.dylib";
    libraryPath = libraryPath;
    logger.info("Library path in Mac: " + libraryPath);
}
else if (Platform.isWindows())
{
    // Windows
    libraryPath = "C:/libsodium/libsodium.dll";
    logger.info("Library path in Windows: " + libraryPath);
}
else
{
    // Linux
    libraryPath = "/usr/local/lib/libsodium.so";
    logger.info("Library path: " + libraryPath);
}

logger.info("loading libsodium...");
SodiumLibrary.setLibraryPath(libraryPath);
// To check the native library is actually loaded, print the version of 
// native sodium library
String v = SodiumLibrary.libsodiumVersionString();
logger.info("libsodium version: " + v);
}
```
If the library could not be loaded Java's ```RuntimeException``` will be thrown.
If the library is loaded successfully, you are ready to make the API calls.

Please look at ```TestInitializeLibrary.java``` to see how the library can be initialized from a static block.

## Version of sodium library

```Java
/**
 * Return the version of native sodium library. After loading the native C library, it is a good idea 
 * to make this call to make sure that the expected version of the sodium library is loaded.
 */
public static String libsodiumVersionString()
```

### Example: Print libsodium version

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)
```java
  logger.info("libsodium version: " + SodiumLibrary.libsodiumVersionString());
```

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

## Secret-key authenticated cryptography

 Excerpt from libsodium documentation:

> This operation:
> * Encrypts a message with a key and a nonce to keep it confidential
> * Computes an authentication tag. This tag is used to make sure that the message hasn't been tampered with before decrypting it.

> A single key is used both to encrypt/sign and verify/decrypt messages. For this reason, it is critical to keep the key confidential.
> The nonce doesn't have to be confidential, but it should never ever be reused with the same key. The easiest way to generate a nonce is to use randombytes_buf().

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

### Encrypt a message with a key and a nonce

```java
/**
 * Encrypts a message with a key and a nonce
 *
 * Parameters:
 *  message    message bytes to encrypt
 *  nonce      nonce bytes. Generate it by calling  public static long cryptoBoxNonceBytes()
 *
 * Returns:
 *  Encrypted cipher text bytes 
 *
 * Throws SodiumLibraryException in case of error
 */

public static byte[] crytoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key)
```

### Verify and decrypt the message

```java
/**
 * Verify and decrypt the message encrypted with crytoSecretBoxEasy()
 *
 * Parameters:
 *   cipherText  - encrypted bytes
 *   nonce        - nonce bytes used during encryption
 *   key          - key bytes used in encryption
 * 
 * Returns:
 *   Decrypted message bytes
 *  
 * Throws SodiumLibraryException in case of error
 */
public static byte[] cryptoSecretBoxOpenEasy(byte[] cipherText,byte[] nonce, byte[] key)
```

### Example: Encrypt and Decrypt a message

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

```java
// don't forget to load the libsodium library first

String message = "This is a message";

// generate nonce
long nonceBytesLength = SodiumLibrary.cryptoSecretBoxNonceBytes();
byte[] nonceBytes = SodiumLibrary.randomBytes((int) nonceBytesLength);
byte[] messageBytes = message.getBytes();

// generate the encryption key
byte[] key = SodiumLibrary.randomBytes((int) SodiumLibrary.cryptoSecretBoxKeyBytes());

// encrypt
byte[] cipherText = SodiumLibrary.cryptoSecretBoxEasy(messageBytes, nonceBytes, key);

// now decrypt
byte[] decryptedMessageBytes = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText, nonceBytes, key);
String decryptedMessage;
try
{
    decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
    System.out.println("Decrypted message: " + decryptedMessageBytes);
} catch (UnsupportedEncodingException e)
{
    e.printStackTrace();
}
```

## Public-key cryptography
### Generate Key Pair

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)

```java
/**
 * Randomly generates a secret key and a corresponding public key
 *
 * Return:
 *   SodiumKeyPair
 */
 public static SodiumKeyPair cryptoBoxKeyPair()
``` 

### Example: Generate key pair

```java

// generate key pair
 SodiumKeyPair kp  = SodiumLibrary.cryptoBoxKeyPair();
 byte[] publicKey  = kp.getPublicKey();
 byte[] privateKey = kp.getPrivateKey();

 String hexPublicKey  = SodiumUtils.binary2Hex(publicKey);
 String hexPrivateKey = SodiumUtils.binary2Hex(privateKey);
```


```java
/**
 * Alice encrypts a message with recipient's (Bob) public key and 
 * creates authentication tag with her private key
 * 
 * Parameters:
 *   message            The message to encrypt
 *   nonce              SodiumLibrary.crytoBoxNonceBytes() bytes of nonce. 
 *                      It must be preserved because it will be needed during decryption
 *   recipientPublicKey Recipient's public key for encrypting the message
 *   senderPrivateKey   Sender's private key for creating authentication tag
 *
 * Returns:
 *    encrypted message as an array of bytes
 */
 public static byte[] cryptoBoxEasy(byte[] message, 
    byte[] nonce
    byte[] recipientPublicKey, byte[] senderPrivateKey) throws SodiumLibraryException
```            

```java
/**
 * Bob (recipient) verifies the message with Alice's (sender) public key and 
 * decrypts the message with his private key
 *
 * Parameters:
 *  cipherText          Message to decrypt
 *  nonce               Nonce used during encryption 
 *  senderPublicKey     Sender's (Alice) public key for verifying message
 *  recipientPrivateKey Recipient's (Bob)  Private key to decrypt the message
 * 
 * Returns: 
 * Decrypted message as an array of bytes.
 * In case of error SodiumLibraryException() run time exception will be thrown 
 */
 public static byte[] cryptoBoxOpenEasy(byte[] cipherText,
    byte[]nonce, 
    byte[] senderPublicKey, byte[] recipientPrivateKey) throws SodiumLibraryException
```

```java
/**
 * Encrypts a message with recipient's public key.
 * 
 * Usage: Alice can anonymously send a message to Bob by encrypting the message 
 * with his public key.
 * 
 * Parameters:
 *  message           The message bytes to encrypt
 * recipientPublicKey Recipient's public key 
 *
 * Rreturn:
 * Encrypted message bytes. The length of the cipher text will be 
 * SodiumLibrary#cryptoBoxSealBytes() + message.length
 *
 * Tthrows SodiumLibraryException on error
 */
 public static byte[] cryptoBoxSeal(byte[] message, byte[] recipientPublicKey) 
    throws SodiumLibraryException
```

```java
/**
 * Decrypts a ciphertext using recipient's  key pair.
 * 
 * Only the recipient can decrypt the message with his private key but the 
 * recipient can not identify the sender.
 * 
 * Parameters:
 *  cipherText Ciphertext to decrypt
 *  pk Recipient's public key
 *  sk Recipient's private Key
 *
 * Returns:
 * Decrypted plaintext bytes. 
 * @throws SodiumLibraryException on error
 */
public static byte[] cryptoBoxSealOpen(byte[] cipherText,byte[] pk, byte[] sk) throws SodiumLibraryException
```

### Example: Alice shares secret with Bob, Bob verifies and decrypt it

1. Alice generates her key pair
2. Bob generate  his key pair
3. Alice (sender) Encrypts a message with Bob's (recipient) public key and creates authentication tag with her private key
4. Bob (recipient) verifies the message with Alice's (sender) public key and decrypts with his private key

```java
// Alice generates key pair
SodiumKeyPair aliceKeyPair = SodiumLibrary.cryptoBoxKeyPair();
byte[] alicePublicKey = aliceKeyPair.getPublicKey();
byte[] alicePrivateKey = aliceKeyPair.getPrivateKey();

// Bob generates key pair
SodiumKeyPair bobKeyPair = SodiumLibrary.cryptoBoxKeyPair();
byte[] bobPublicKey = bobKeyPair.getPublicKey();
byte[] bobPrivateKey = bobKeyPair.getPrivateKey();

// Generate nonce
byte[] nonce = SodiumLibrary.randomBytes((int) SodiumLibrary.cryptoBoxNonceBytes());

String secretMessage = "Hi Bob, This is Alice";
// Alice encrypts the message with Bob's public key, creates authentication tag
// with her private key
byte[] cipherText = SodiumLibrary.cryptoBoxEasy(
    secretMessage.getBytes(), nonce, 
    bobPublicKey,
    alicePrivateKey);
String cipherHex = SodiumUtils.binary2Hex(cipherText);
logger.info("Ciphertext: " + cipherHex);

// Bob Verifies with Alice's public key and decrypts ciphertext with his Private key
byte[] decrypted = SodiumLibrary.cryptoBoxOpenEasy(
        cipherText, nonce,
        alicePublicKey,
        bobPrivateKey);
String decrypteString;
try
{
    decrypteString = new String(decrypted, "UTF-8");
    logger.info("decrypted: " + decrypteString);
} catch (UnsupportedEncodingException e)
{
    e.printStackTrace();
}
```

### Example: Alice (sender) anonymously encrypts message with Bob's (recipient) public key

```java
// Bob generates key pair
SodiumKeyPair bobKeyPair = SodiumLibrary.cryptoBoxKeyPair();
byte[] bobPublicKey = bobKeyPair.getPublicKey();
byte[] bobPrivateKey = bobKeyPair.getPrivateKey();

String secretMessage = "Hi Bob, This is Alice";
// Alice encrypts with Bob's public key
byte[] cipherText = SodiumLibrary.cryptoBoxSeal(secretMessage.getBytes(), bobPublicKey);
String cipherHex = SodiumUtils.binary2Hex(cipherText);
logger.info("Ciphertext: " + cipherHex);
logger.info("Ciphertext length : " + cipherText.length);

long ciperTextlength = SodiumLibrary.cryptoBoxSealBytes() + secretMessage.length();
logger.info("length: " + ciperTextlength);
```

### Example: Bob (recipient) decrypts the message with his private key

```java
// Bob decrypts with his private key
byte[] decrypted = SodiumLibrary.cryptoBoxSealOpen(cipherText, bobPublicKey, bobPrivateKey);

try
{
    String decrypteString = new String(decrypted, "UTF-8");
    logger.info("decrypted: " + decrypteString);
} catch (UnsupportedEncodingException e)
{
    e.printStackTrace();
}
```


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
 *   algorithm as crypto_pwhash_alg_argon2i13()
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


## How to encrypt a private key

This instruction is for encrypting something with a symmetric memory hardened key derived from a passphrase and use that key in encryption. I am giving the example on encrypting a private key as this is a very common requirement.

When the public and private key pair is generated and if it is required to store the private key, the private key must be properly encrypted and stored.
The following procedure can be used to encrypt the private key:

### Encrypting the private key
* Come up with a _strong_ pass phrase. Use a long memorable pass phrase. This is the most important defense against brute force 
cracking.

* Generate cryptoPwhashSaltBytes() long salt

```java
  byte[] salt = SodiumLibrary.randomBytes(SodiumLibrary.cryptoPwhashSaltBytes);
```

* Derive a brute force resistant key from the pass phrase

```java
  byte[] key = SodiumLibrary.cryptoPwhashArgon2i(passPhrase, salt);
```

* _Store_ the salt. This will be used to derive the same key again from the pass phrase

* Generate cryptoSecretBoxNonceBytes() long nonce

```java
  byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxNonceBytes());
```

* Encrypt the private key 

```java
  byte[] encryptedPrivateKey = SodiumLibrary.cryptoSecretBoxEasy(privateKey, nonce, key);
```

* _Store_ nonce and the encrypted private key

### Decrypting the private key

* Derive the encryption key from the pass phrase and stored salt

```java
  byte[] key = SodiumLibrary.cryptoPwhashArgon2i(passPhraseBytes, saltBytes);
```

* Verify and decrypt the private key with the derived key and stored nonce

```java
  byte[] privateKey = SodiumLibrary.cryptoSecretBoxOpenEasy(encryptedPrivateKey, nonce, key);
```

# If your project is not a maven project

If your project is not a maven project, find out the dependencies of libsodium-jna and obtain the jar files from maven
central manually and add them to your build path

* find the dependencies

```
    $ cd libsodium-jna
    $ mvn dependency:tree
...
[INFO] ------------------------------------------------------------------------
[INFO] Building com.muquit.libsodiumjna 1.0.1
[INFO] ------------------------------------------------------------------------
[INFO] 
[INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ libsodium-jna ---
[INFO] com.muquit.libsodiumjna:libsodium-jna:jar:1.0.1
[INFO] +- net.java.dev.jna:jna:jar:4.2.2:compile
[INFO] +- org.slf4j:slf4j-api:jar:1.7.21:compile
[INFO] +- org.slf4j:slf4j-log4j12:jar:1.7.21:compile
[INFO] |  \- log4j:log4j:jar:1.2.17:compile
[INFO] +- commons-codec:commons-codec:jar:1.10:compile
[INFO] \- junit:junit:jar:4.11:test
[INFO]    \- org.hamcrest:hamcrest-core:jar:1.3:test
...    
```

# License is MIT

MIT
