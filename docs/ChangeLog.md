# v1.0.5

* Update JNA version to 5.14.0 from 5.5.0 in order to support Apple silicon. No code change.
  Tested with libsodium 1.0.20

(Aug-31-2024 )

## Update (Feb-02-2026)
* No code change. v1.0.5 is still the stable version.
* Updated main branch with single `pom.xml` to support JDK 8 to JDK 21.  
Previously required separate `pom.xml` (JDK 8) and `pom_java11.xml`
(JDK 11+). `slf4j` deprecated `slf4j-log4j12`, now they created 
`reload4j`. Updated `pom.xml` for that. Use @MARKDOWN_TOC@ to 
generate docs.

## Update (Feb-04-2026)
* Add instructions on how to use from a Gradle project.
* Add gradle test

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

