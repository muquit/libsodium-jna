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
  byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxNonceBytes().intValue());
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

