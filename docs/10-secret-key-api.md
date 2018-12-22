## Secret-key cryptography

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|[```crypto_secretbox_easy()```](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html)| ```public static byte[] cryptoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key)``` |Encrypts a message with a key and a nonce|
|[```crypto_secretbox_open_easy()```](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html)|```public static byte[] cryptoSecretBoxOpenEasy(byte[] cipherText,byte[] nonce, byte[] key)```|Verifies and decrypts an encrypted message produced by ```cryptoSecretBoxEasy()```|
|```crypto_secretbox_detached()```|```public static SodiumSecretBox cryptoSecretBoxDetached(byte[] message, byte[] nonce, byte[] key)```|Encrypts a message with a key and a nonce and returns authentication tag with the encrypted message|
|```crypto_secretbox_open_detached()```|```public static byte[] cryptoSecretBoxOpenDetached(SodiumSecretBox secretBox, byte[] nonce, byte[] key)```|Verifies and decrypts an encrypted message, authentication tag used in ```cryptoSecretBoxDetached()``` is needed|
|```crypto_auth()```|```public static byte[] cryptoAuth(byte[] message, byte[] key)```|Computes an authentication tag for a message | 
|```crypto_auth_verify()```|```public static boolean cryptoAuthVerify(byte[] mac, byte[] message, byte[] key)```|Verifies the authentication tag for a message|
|```crypto_secretbox_keybytes()```|```public static NativeLong cryptoSecretBoxKeyBytes()```|Length of key. The API will be changed to reutrn int in next version|
|```crypto_secretbox_noncebytes()```|```public static NativeLong cryptoSecretBoxNonceBytes()```|Length of nonce. The API will be changed to reutrn int in next version|
|```crypto_secretbox_macbytes()```|```public static NativeLong cryptoSecretBoxMacBytes()```|Length of authentication code. The API will be changed to reutrn int in next version|

