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
// This API will be changed to return int in future version of libsodium-jna
byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoBoxNonceBytes().intValue());

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

