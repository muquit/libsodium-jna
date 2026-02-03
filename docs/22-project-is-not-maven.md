# If your project is not a maven project

If your project is not a maven project, find out the dependencies of 
libsodium-jna and obtain the jar files from maven central manually and add 
them to your build path

* find the dependencies

```
    $ cd libsodium-jna
    $ mvn dependency:tree
...
[INFO] ---------------< com.muquit.libsodiumjna:libsodium-jna >----------------
[INFO] Building com.muquit.libsodiumjna 1.0.5
[INFO]   from pom.xml
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[INFO] --- dependency:3.7.0:tree (default-cli) @ libsodium-jna ---
[INFO] com.muquit.libsodiumjna:libsodium-jna:jar:1.0.5
[INFO] +- net.java.dev.jna:jna:jar:5.13.0:compile
[INFO] +- org.slf4j:slf4j-api:jar:1.7.36:compile
[INFO] +- org.slf4j:slf4j-reload4j:jar:1.7.36:test
[INFO] |  \- ch.qos.reload4j:reload4j:jar:1.2.19:test
[INFO] +- commons-codec:commons-codec:jar:1.15:compile
[INFO] \- junit:junit:jar:4.13.2:test
[INFO]    \- org.hamcrest:hamcrest-core:jar:1.3:test
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
...    
```

