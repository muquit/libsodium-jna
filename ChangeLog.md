
<!-- TOC -->

- [v1.0.5](#v105)
- [v1.0.4](#v104)
- [v1.0.3](#v103)
- [v1.0.2](#v102)
- [v1.0.1](#v101)

<!-- /TOC -->

# v1.0.5

* Update JNA version to 5.14.0 from 5.5.0 in order to support Apple silicon. No code change.
  Tested with libsodium 1.0.20

(Aug-31-2024 )

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

