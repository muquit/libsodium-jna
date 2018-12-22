## Public-key cryptography

| native libsodium C API| java binding |Description|
|-----------------------|--------------|-----------|
|[```crypto_box_keypair()```](https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption.html)|[```public static SodiumKeyPair cryptoBoxKeyPair()```](#generate-key-pair)|Randomly generate a private key and a corresponding public key |
|```crypto_scalarmult_base()```|```public static byte[] cryptoPublicKey(byte[] privateKey)```|Compute public key given a private key|
|```crypto_box_easy()```|```public static byte[] cryptoBoxEasy(byte[] message, byte[] nonce, byte[] publicKey, byte[] privateKey)```|Encrypts a message with a recipient's public key, sender's private key and a nonce|
|```crypto_box_open_easy()```|```public static byte[] cryptoBoxOpenEasy(byte[] cipherText, byte[]nonce, byte[] publicKey, byte[] privateKey)```|Verifies and decrypts an encrypted message produced by ```cryptoBoxEasy()```|
|```crypto_box_seal()```|```public static byte[] cryptoBoxSeal(byte[] message, byte[] recipientPublicKey)```|Encrypts a message for a recipient with recipient's public key|
|```crypto_box_seal_open()```|```public static byte[] cryptoBoxSealOpen(byte[] cipherText,byte[] pk, byte[] sk)```|Decrypts an encrypted message with the key pair public key and private key|
|```crypto_box_noncebytes()```|```public static NativeLong cryptoBoxNonceBytes()```|Length of nonce. The API will be changed to reutrn int in next version|
|```crypto_box_seedbytes()```| ```public static NativeLong crytoBoxSeedBytes()```|Length of key seed. The API will be changed to reutrn int in next version |
|```crypto_box_publickeybytes()```|```public static NativeLong crytoBoxPublicKeyBytes()```|Length of public key. The API will be changed to reutrn int in next version|
|```crypto_box_secretkeybytes()```|```public static NativeLong crytoBoxSecretKeyBytes()```|Length of private key. The API will be changed to reutrn int in next version|
|```crypto_box_macbytes()```|```public static NativeLong cryptoBoxMacBytes()```|Length of mac. The API will be changed to reutrn int in next version|
|```crypto_box_sealbytes()```|```public static NativeLong cryptoBoxSealBytes()```|Length of seal. The API will be changed to reutrn int in next version|

