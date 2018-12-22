## Version of sodium library

```Java
/**
 * Return the version of native sodium library. After loading the native C library, it is a good idea 
 * to make this call to make sure that the expected version of the sodium library is loaded.
 */
public static String libsodiumVersionString()
```

### Example: Print libsodium version

Make sure to [Load the libsodium C Library first](#load-the-libsodium-c-library-first)
```java
  logger.info("libsodium version: " + SodiumLibrary.libsodiumVersionString());
```

