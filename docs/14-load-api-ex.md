## Load the libsodium C Library first

Before making call to any API, the native *sodium C library*  must be loaded explicitly from a specific path. It is possible to load the library
from path, however *libsodium-jna* is designed to load *sodium library* explicitly from a path.

### Example: Load the native libsodium library

```java
private static String libraryPath = null;

if (Platform.isMac())
{
    // MacOS
    libraryPath = "/usr/local/lib/libsodium.dylib";
    libraryPath = libraryPath;
    logger.info("Library path in Mac: " + libraryPath);
}
else if (Platform.isWindows())
{
    // Windows
    libraryPath = "C:/libsodium/libsodium.dll";
    logger.info("Library path in Windows: " + libraryPath);
}
else
{
    // Linux
    libraryPath = "/usr/local/lib/libsodium.so";
    logger.info("Library path: " + libraryPath);
}

logger.info("loading libsodium...");
SodiumLibrary.setLibraryPath(libraryPath);
// To check the native library is actually loaded, print the version of 
// native sodium library
String v = SodiumLibrary.libsodiumVersionString();
logger.info("libsodium version: " + v);
}
```
If the library could not be loaded Java's ```RuntimeException``` will be thrown.
If the library is loaded successfully, you are ready to make the API calls.

Please look at ```TestInitializeLibrary.java``` to see how the library can be initialized from a static block.

