# Requirements

* jdk 1.7+. The default `pom.xml` is for jdk upto 1.8. For [jdk11](https://jdk.java.net/11/), use `pom_java11.xml`

* maven must be installed in order to create the jar file. However, it is possible to use the library in a 
non-maven project.

* [libsodium](https://libsodium.org) 1.0.11 or higher. libsodium-jna itself does not enforce version checking but make sure you are using libsodium v 1.0.11 or higher. Please note that the algorithm used in ```cryptoPwhashArgon2i()``` may change from version to version of libsodium, to make sure, please look at [ChangeLog](ChangeLog.md).

* Make sure native [libsodium](https://libsodium.org) is already installed in the system. This library does not come with native version of libsodium. *It is a good idea to compile and install [libsodium](https://libsodium.org) yourself instead of using one from the Internet*.

* This library does not load any libsodium library from path, rather you have to specify exactly where the library is located. 

