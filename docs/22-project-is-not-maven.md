# If your project is not a maven project

If your project is not a maven project, find out the dependencies of libsodium-jna and obtain the jar files from maven
central manually and add them to your build path

* find the dependencies

```
    $ cd libsodium-jna
    $ mvn dependency:tree
...
[INFO] ------------------------------------------------------------------------
[INFO] Building com.muquit.libsodiumjna 1.0.1
[INFO] ------------------------------------------------------------------------
[INFO] 
[INFO] --- maven-dependency-plugin:2.8:tree (default-cli) @ libsodium-jna ---
[INFO] com.muquit.libsodiumjna:libsodium-jna:jar:1.0.1
[INFO] +- net.java.dev.jna:jna:jar:4.2.2:compile
[INFO] +- org.slf4j:slf4j-api:jar:1.7.21:compile
[INFO] +- org.slf4j:slf4j-log4j12:jar:1.7.21:compile
[INFO] |  \- log4j:log4j:jar:1.2.17:compile
[INFO] +- commons-codec:commons-codec:jar:1.10:compile
[INFO] \- junit:junit:jar:4.11:test
[INFO]    \- org.hamcrest:hamcrest-core:jar:1.3:test
...    
```

