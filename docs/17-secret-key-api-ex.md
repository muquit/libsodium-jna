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
 *  nonce      nonce bytes. Generate it by calling  public static NativeLong cryptoBoxNonceBytes()
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
int nonceBytesLength = SodiumLibrary.cryptoSecretBoxNonceBytes().intValue();
byte[] nonceBytes = SodiumLibrary.randomBytes(nonceBytesLength);
byte[] messageBytes = message.getBytes();

// generate the encryption key
byte[] key = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());

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

