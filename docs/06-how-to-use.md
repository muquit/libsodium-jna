# How to use
## Install native libsodium C library  first

* Compile and Install libsodium. It is a requirement.
  * Download [libsodium-1.0.20.tar.gz](https://download.libsodium.org/libsodium/releases/)
  * make sure ```pkg-config``` is installed
  
Follow the instructions on [libsodium doc](https://download.libsodium.org/doc/) page on how to compile and install. I do the following on Linux and Mac OS X:

```
  tar -xf libsodium-1.0.20.tar.gz
  cd libsodium-1.0.20
  ./configure
  make && make check
  sudo make install
  sudo ldconfig
```
## Update your project's ```pom.xml```

Add the following block inside dependencies block:

```
    <!--  As of v1.0.5, libsodium-jna is in the maven central. -->
    <dependency>
        <groupId>com.muquit.libsodiumjna</groupId>
        <artifactId>libsodium-jna</artifactId>
        <version>1.0.5</version>
    </dependency>
```
**Update: Feb-18-2020**. libsodium-jna in Maven central uses Java Native Access v4.2.2. This version of
JNA has issues with some version of Microsoft Windows e.g. it does not work in
Windows Server 2019. If you are using libsodium-jna  from Maven in your
project, please update the JNA version to the latest in your pom.xml as follows:

```
    <!-- https://mvnrepository.com/artifact/net.java.dev.jna/jna -->
    <dependency>
        <groupId>net.java.dev.jna</groupId>
        <artifactId>jna</artifactId>
        <version>5.14.0</version>
    </dependency>
```


Note: If you do not use maven, look at the end of the document.

## If you want to Install ```libsodium-jna``` from trunk

Trunk contains the latest development code but mostly stable. I try not to
check-in broken code.

```
    git clone https://github.com/muquit/libsodium-jna.git
    cd libsodium-jna
    mvn clean install
    mvn test
```
To compile with [java 11](https://jdk.java.net/11/):

```
mvn -f pom_java11.xml clean install
mvn -f pom_java11.xml test
```

To load the project in Eclipse, select _File->Import...->Maven->Existing Maven Projects_, then Click on *Next >*, click on *Browse...* button and select the libsodium-jna directory.


