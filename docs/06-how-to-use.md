# How to use
## Install native libsodium C library first
* Compile and Install libsodium. It is a requirement.
  * Download @LIBSODIUM_LATEST@
  * make sure ```pkg-config``` is installed
  
Follow the instructions on @LIBSODIUM_DOC@ page on how to compile and install. I do the following on Linux and Mac OS X:
```
  tar -xf libsodium-1.0.21.tar.gz
  cd libsodium-1.0.21
  ./configure
  make && make check
  sudo make install
  sudo ldconfig
```

## Add libsodium-jna to your project

### Maven
Add the following block inside the dependencies block of your `pom.xml`:
```xml
<!--  As of v1.0.5, libsodium-jna is in the maven central. -->
<dependency>
    <groupId>com.muquit.libsodiumjna</groupId>
    <artifactId>libsodium-jna</artifactId>
    <version>1.0.5</version>
</dependency>
```

**Update: Feb-18-2020**. libsodium-jna in Maven central uses Java Native Access v4.2.2. This version of
JNA has issues with some version of Microsoft Windows e.g. it does not work in
Windows Server 2019. If you are using libsodium-jna from Maven in your
project, please update the JNA version to the latest in your pom.xml as follows:
```xml
<!-- https://mvnrepository.com/artifact/net.java.dev.jna/jna -->
<dependency>
    <groupId>net.java.dev.jna</groupId>
    <artifactId>jna</artifactId>
    <version>5.14.0</version>
</dependency>
```

### Gradle
Add the following to your `build.gradle`:
```gradle
dependencies {
    implementation 'com.muquit.libsodiumjna:libsodium-jna:1.0.5'
}
```

If you need to override the JNA version (recommended for Windows Server 2019 and newer):
```gradle
dependencies {
    implementation 'com.muquit.libsodiumjna:libsodium-jna:1.0.5'
    implementation 'net.java.dev.jna:jna:5.14.0'
}
```

Note: If you do not use Maven or Gradle, look at the end of the document.

## If you want to install ```libsodium-jna``` from source
The main branch contains stable code.
```
git clone https://github.com/muquit/libsodium-jna.git
cd libsodium-jna
```
### Maven
```bash
mvn clean install
mvn test
```

### Gradle
**Note:** Building with Gradle 9.x requires JDK 17+, though Maven works with 
JDK 8+. The compiled library works on JDK 8+.
```bash
gradle clean build publishToMavenLocal
gradle test
```

Please look at @MAKEFILE@ for various targets.

To load the project in Eclipse, select _File->Import...->Maven->Existing Maven Projects_, then Click on *Next >*, click on *Browse...* button and select the libsodium-jna directory.
