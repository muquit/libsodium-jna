package test.com.muquit.libsodiumjna;

import com.muquit.libsodiumjna.SodiumLibrary;
import com.sun.jna.Platform;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class TestSodiumGradle {
    private String libraryPath;
    
    @Before
    public void initSodium() {
        String platform = System.getProperty("os.name");
        System.out.println("Platform: " + platform);
        
        if (Platform.isMac()) {
            libraryPath = "/usr/local/lib/libsodium.dylib";
            System.out.println("Library path in Mac: " + libraryPath);
        } else if (Platform.isWindows()) {
            libraryPath = "C:/libsodium/libsodium.dll";
            System.out.println("Library path in Windows: " + libraryPath);
        } else {
            libraryPath = "/usr/local/lib/libsodium.so";
            System.out.println("Library path in " + platform + ": " + libraryPath);
        }
        
        System.out.println("Initialize libsodium...");
        SodiumLibrary.setLibraryPath(libraryPath);
    }
    
    @Test
    public void testLibraryVersion() {
        String version = SodiumLibrary.libsodiumVersionString();
        System.out.println("libsodium version: " + version);
        assertNotNull("Version should not be null", version);
        assertTrue("Version should start with 1.0", version.startsWith("1.0"));
    }
}
