package com.muquit.libsodiumjna;

import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

/**
 * Java binding to <a href="https://download.libsodium.org/doc/" target="_blank">libsodium</a> crypto C APIs. All the methods are
 * static methods. Most methods throw {@link com.muquit.libsodiumjna.exceptions.SodiumLibraryException} at run time
 * in case of errors.
 * 
 * @author muquit@muquit.com - Oct 21, 2016, 11:37:24 AM - first cut
 * 
 * @see <a href="https://download.libsodium.org/doc/" target="_blank">libsodium</a> documentation
 */
public class SodiumLibrary
{
    private final static Logger logger = LoggerFactory.getLogger(SodiumLibrary.class);
    
    private static String libPath;
    
    private SodiumLibrary(){}
    
    public static void log(String msg)
    {
        System.out.println("MMMM: " + msg);
    }
    
   /**
    * Set the absolute path of the libsodium shared library/DLL. This method 
    * must be called before calling any methods. Although JNA supports loading
    * a shared library from path, libsodium-jna requires specifying the absolute
    * path to make sure that the exact library is being loaded.
    *<p> 
    * @param libraryPath The absolute path of the libsodium library. For example,
    * in Linux, it might be <code>/usr/local/lib/libsodium.so</code>, in Windows, 
    * it might be <code>c:/libs/libsodium.dll</code>, in MacOS, it might be 
    * <code>/usr/local/lib/libsodium.dylib</code> etc. The point is there is no
    * ambiguity
    * 
    * @author muquit@muquit.com - Oct 17, 2016, 12:16:50 PM - first cut
    */
    public static void setLibraryPath(String libraryPath)
    {
        SodiumLibrary.libPath = libraryPath;
    }
    
    /**
     * @return path of library set by SodiumLibary.setLibraryPath()
     * @author muquit@muquit.com - Oct 21, 2016, 3:03:59 PM - first cut
     */
    public static String getLibaryPath()
    {
        return SodiumLibrary.libPath;
    }

    /**
     * @return The singleton Sodium object. The singleton pattern is adapted from 
     * kalium java library. Other than that, this library does not use any code
     * from kalium.
     *<p> 
     * Although libsodium seems to be thread safe now, the code is written 
     * sometime back and I don't have plan to remove it at this time. 
     * 
     * @author muquit@muquit.com 
     * 
     * @throws RuntimeException at run time if the libsodium library path 
     * is not set by calling <code>SodidumLibary.setLibraryPath(path)</code>.
     */
    public static Sodium sodium()
    {
        if (SodiumLibrary.libPath == null)
        {
            logger.info("libpath not set, throw exception");
            throw new RuntimeException("Please set the absolute path of the libsodium libary by calling SodiumLibrary.setLibraryPath(path)");
        }
        Sodium sodium = SingletonHelper.instance;
        String h = Integer.toHexString(System.identityHashCode(sodium));
        int rc = sodium.sodium_init();
        if (rc == -1)
        {
            logger.error("ERROR: sodium_init() failed: " + rc);
            throw new RuntimeException("sodium_init() failed, rc=" + rc);
        }
        return sodium;
    }

    private static final class SingletonHelper
    {
        public static final Sodium instance = (Sodium) Native.loadLibrary(libPath,Sodium.class);
    }

    /**
     * Declare all the supported libsodium functions in this interface and 
     * implement them in this class as static methods.
     * 
     * @author muquit@muquit.com - Oct 21, 2016, 11:44:45 AM - first cut
     */
    public interface Sodium extends Library
    {
        int sodium_library_version_major();
        int sodium_library_version_minor();
        int sodium_init();

        /**
         * @return version string of the libsodium library
         * include/sodium/version.h
         */
        String sodium_version_string();
        
        /**
         * Fills size bytes starting at buf with an unpredictable sequence of bytes.
         * @param buf  buffer to fill with random bytes
         * @param size number of random bytes
         * <a href="https://download.libsodium.org/doc/generating_random_data/">Generating random data</a> libsodium page
         */
        void randombytes_buf(byte[] buf, int size);

        /**
         * 
         * see include/sodium/crypto_pwhash.h
         */
        int crypto_pwhash_alg_argon2i13();
        int crypto_pwhash_alg_default();
        int crypto_pwhash_saltbytes();
        int crypto_pwhash_strbytes();
        Pointer crypto_pwhash_strprefix();
        long crypto_pwhash_opslimit_interactive();
        NativeLong crypto_pwhash_memlimit_interactive();
        long crypto_pwhash_opslimit_moderate();
        NativeLong crypto_pwhash_memlimit_moderate();
        long crypto_pwhash_opslimit_sensitive();
        NativeLong crypto_pwhash_memlimit_sensitive();
        
        /* sodium/crypto_box.h */
        long crypto_box_seedbytes();
        long crypto_box_publickeybytes();
        long crypto_box_secretkeybytes();
        long crypto_box_noncebytes();
        long crypto_box_macbytes();
        long crypto_box_sealbytes();

        /* sodium/crypto_auth.h */
        long crypto_auth_bytes();
        long crypto_auth_keybytes();
        
        int crypto_pwhash(byte[] key, long keylen, 
                byte[] passwd, long passwd_len,
                byte[] in_salt, 
                long opslimit, 
                NativeLong memlimit, 
                int alg);
        
        int crypto_pwhash_scryptsalsa208sha256(byte[] key, long keyLength,
                byte[] passwd, long passwd_len,
                byte[] in_salt, 
                long opslimit, 
                NativeLong memlimit);
        
        int crypto_pwhash_str(byte[] hashedPassword, 
                byte[] password, long passwordLen, 
                long opslimit, NativeLong memlimit);
        
        int crypto_pwhash_str_verify(byte[] hashedPassword,
                byte[] password, long passwordLen);
        
        /* sodium/crypto_pwhash_scryptsalsa208sha256.h */
        long crypto_pwhash_scryptsalsa208sha256_saltbytes();
        
        /* Secret Key */
        long  crypto_secretbox_keybytes();
        long  crypto_secretbox_noncebytes();
        long  crypto_secretbox_macbytes();        
        
        int crypto_secretbox_easy(byte[] cipherText, 
                byte[] message, long mlen, byte[] nonce,
                byte[] key);
        
        int crypto_secretbox_open_easy(byte[] decrypted, 
                byte[] cipherText, long ct_len, byte[] nonce,
                byte[] key);
        
        int crypto_secretbox_detached(byte[] cipherText,
                byte[] mac,
                byte[] message, long mlen,
                byte[] nonce, byte[] key);
        
        int crypto_secretbox_open_detached(byte[] message,
                byte[] cipherText, byte[] mac, long cipherTextLength,
                byte[] nonce, byte[] key);
        
        int crypto_box_seal(byte[] cipherText,
                byte[] message, long messageLen,
                byte[] recipientPublicKey);
        
        int crypto_box_seal_open(byte[] decrypted,
                byte[] cipherText, long cipherTextLen,
                byte[] recipientPublicKey, byte[] reciPientPrivateKey);
        
        int crypto_auth(byte[] mac, byte[] message, long messageLen, byte[] key);
        int crypto_auth_verify(byte[] mac, byte[] message, long messagelen, byte[] key);
        
        
        /* Public key authenticated encryption */
        int crypto_box_keypair(byte[] pk, byte[] sk);
        
       /**
        * Compute Public key from Private Key
        * @param pk - Public Key returns
        * @param sk - Private Key
        * @return 0 on success -1 on failure
        * @author muquit@muquit.com - Oct 18, 2016, 4:39:20 PM - first cut
        */
        int crypto_scalarmult_base(byte[] pk, byte[] sk);
        
        int crypto_box_easy(byte[] cipher_text,
                byte[] plain_text, long pt_len,
                byte[] nonce,
                byte[] public_key, byte[] private_key);

        int crypto_box_open_easy(byte[] decrypted, byte[] cipher_text,
                long ct_len, byte[] nonce,
                byte[] public_key, byte[] private_key);
    }

    ////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////

    /**
     * @return version string of libsodium
     */
    public static String libsodiumVersionString()
    {
        return sodium().sodium_version_string();
    }
    
    
   /**
    * Return unpredictable sequence of bytes.
    * <p>
    * Excerpt from libsodium documentation:
    * <blockquote>
    * <ul>
    * <li> On Windows systems, the <code>RtlGenRandom()</code> function is used
    * <li> On OpenBSD and Bitrig, the <code>arc4random()</code> function is used
    * <li> On recent Linux kernels, the getrandom system call is used (since Sodium 1.0.3)
    * <li> On other Unices, the /dev/urandom device is used
    * <li>If none of these options can safely be used, custom implementations can easily be hooked.
    * </ul>
    * </blockquote>
    * <p>
    * @param  size Number of random bytes to generate
    * <p>
    * @return Array of random bytes
    * <p>
    * @author muquit@muquit.com - Oct 21, 2016
    * <p>
    * @see <a href="https://download.libsodium.org/doc/generating_random_data/" target="_blank">Generating random data</a> in libsodium page
    */
    public static byte[] randomBytes(int size)
    {
        byte[] buf = new byte[size];
        sodium().randombytes_buf(buf, size);
        return buf;
    }
    /*
        int crypto_pwhash(byte[] key, long keylen, 
                byte[] passwd, long passwd_len,
                byte[] in_salt, 
                long opslimit, 
                NativeLong memlimit, 
                int alg);
                */

    public static byte[] cryptoPwhash(byte[] passwd, byte[] salt, long opsLimit, NativeLong memLimit, int algorithm) throws SodiumLibraryException
    {
        byte[] key = new byte[(int) sodium().crypto_box_seedbytes()];
        logger.info(">>> NavtiveLong size: " + NativeLong.SIZE * 8 + " bits");
        
        int rc = sodium().crypto_pwhash(key, key.length, 
                passwd, passwd.length,
                salt,
                opsLimit,
                memLimit,
                algorithm);
        
        logger.info("crypto_pwhash returned: " + rc);
        if (rc != 0)
        {
            throw new SodiumLibraryException("cryptoPwhash libsodium crypto_pwhash failed, returned " + rc + ", expected 0");
        }
        return key;

    }
    
    /**
     * Derive a key using Argon2i password hashing scheme
     * <p>
     * The following is taken from <a href="https://download.libsodium.org/doc/password_hashing/">libsodium documentation</a>:
     * <blockquote>
     * Argon2 is optimized for the x86 architecture and exploits the cache and memory organization of the recent Intel 
     *<br>
     * and AMD processors. But its implementation remains portable and fast on other architectures.
     *<p>
     * Argon2 has two variants: Argon2d and Argon2i. Argon2i uses data-independent memory access, which is preferred 
     * <br>
     * for password hashing and password-based key derivation. Argon2i also makes multiple passes over the memory to 
     * <br>
     * protect from tradeoff attacks.
     *<p>
     * This is the variant implemented in Sodium since version 1.0.9.
     *<p> 
     * Argon2 is recommended over Scrypt if requiring libsodium &gt;= 1.0.9 is not a concern.
     * </blockquote>
     * 
     * @param passwd Array of bytes of password
     * @param salt Salt to use in key generation. The salt should be unpredictable and can be generated by calling SodiumLibary.randomBytes(int)
     * The salt should be saved by the caller as it will be needed to derive the key again from the 
     * password.
     * @return Generated key as an array of bytes
     * @throws SodiumLibraryException if libsodium's crypto_pwhash() does not return 0
     *<p> 
     * <code>crypto_pwhash()</code> in <a href="https://download.libsodium.org/doc/password_hashing/">Password hashing</a>
     * libsodium page. <a href="https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf">Argon2i v1.3 Algorithm</a>. 
     * <p>
     * Example:
     * <pre>
     * {@code
     * 
    String password = "This is a Secret";
    salt = SodiumLibary.randomBytes(sodium().crypto_pwhash_saltbytes());
    byte[] key = SodiumLibary.cryptoPwhashArgon2i(password.getBytes(),salt);
    String keyHex = SodiumUtils.bin2hex(key);
     *}
     *</pre>
     */
    public static byte[] cryptoPwhashArgon2i(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        int saltLength = cryptoPwhashSaltBytes();
        if (salt.length != saltLength)
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + saltLength + " bytes");
        }

        byte[] key = new byte[(int) sodium().crypto_box_seedbytes()];
        logger.info(">>> NavtiveLong size: " + NativeLong.SIZE * 8 + " bits");
        logger.info(">>> opslimit: " + sodium().crypto_pwhash_opslimit_interactive());
        logger.info(">>> memlimit: " +  sodium().crypto_pwhash_memlimit_interactive());
        logger.info(">>> alg: " +  sodium().crypto_pwhash_alg_argon2i13());
        
        int rc = sodium().crypto_pwhash(key, key.length, 
                passwd, passwd.length,
                salt,
                sodium().crypto_pwhash_opslimit_interactive(),
                sodium().crypto_pwhash_memlimit_interactive(),
                sodium().crypto_pwhash_alg_argon2i13());
        
        logger.info("crypto_pwhash returned: " + rc);
        if (rc != 0)
        {
            throw new SodiumLibraryException("cryptoPwhashArgon2i libsodium crypto_pwhash failed, returned " + rc + ", expected 0");
        }
        return key;
    }
    
    /**
     * A helper function to call cryptoPwhashArgon2i()
     * 
     * @param passwd Password bytes
     * @param salt   Salt bytes
     * @return key bytes
     * @throws SodiumLibraryException
     * <p>
     * @author muquit@muquit.com - Mar 18, 2017
     */
    public static byte[] deriveKey(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        return cryptoPwhashArgon2i(passwd, salt);
    }
    
    
    /**
     * Return US-ASCII encoded key derives from the password
     * 
     * @param password  password to use in key derivation
     * @return US-ASCII encoded string
     * @throws SodiumLibraryException
     * <p>
     * @author muquit@muquit.com - Oct 22, 2016
     */
    public static String cryptoPwhashStr(byte[] password) throws SodiumLibraryException
    {
        byte[] hashedPassword = new byte[sodium().crypto_pwhash_strbytes()];
        int rc = sodium().crypto_pwhash_str(hashedPassword,
                password, password.length,
                sodium().crypto_pwhash_opslimit_interactive(),
                sodium().crypto_pwhash_memlimit_interactive());
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_pwhash_str failed, returned " + rc + ", expected 0");
        }
        String usAscii = new String(hashedPassword,StandardCharsets.US_ASCII);

        return usAscii;
    }

    /**
     * Verify a US-ASCII encoded key derived previously by calling SodiumLibrary.cryptoPwhashStr(byte[])
     * 
     * @param usAsciiKey key in US ASCII
     * @param password bytes
     * @return true if the key can be verified false otherwise
     * <p>
     * @author muquit@muquit.com - Oct 22, 2016
     */
    public static boolean cryptoPwhashStrVerify(String usAsciiKey, byte[] password)
    {
        byte[] keyBytes = usAsciiKey.getBytes(StandardCharsets.US_ASCII);
        int rc = sodium().crypto_pwhash_str_verify(keyBytes, password, password.length);
        if (rc == 0)
        {
            return true;
        }
        return false;
    }
    
    
    /**
     * Derive key from a password using scrypt
     * <p>
     * Excerpt from libsodium documentation:
     * <blockquote>
     * Scrypt was also designed to make it costly to perform large-scale custom hardware attacks by requiring large 
     * amounts of memory.
     * <p>
     * Even though its memory hardness can be significantly reduced at the cost of extra computations, this function 
     * remains an excellent choice today, provided that its parameters are properly chosen.
     * <p>
     * Scrypt is available in libsodium since version 0.5.0, which makes it a better choice than Argon2 if compatibility with older libsodium versions is a concern.
     * </blockquote>
     * 
     * @param passwd Array of bytes of password
     * @param salt   Salt to use in key generation. The salt should be 
     * unpredictable and can be generated by calling SodiumLibary.randomBytes(int)
     * The salt should be saved by the caller as it will be needed to derive the key again from the 
     * password.
     * @return key as an array of bytes
     * @throws SodiumLibraryException
     * 
     * <code>crypto_pwhash()</code> in <a href="https://download.libsodium.org/doc/password_hashing/">Password hashing</a>
     * libsodium page. 
     */
    public static byte[] cryptoPwhashScrypt(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        long salt_length = sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
        if (salt.length != salt_length)
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + salt_length + " bytes");
        }
        byte[] key = new byte[(int) sodium().crypto_box_seedbytes()];
        int rc = sodium().crypto_pwhash_scryptsalsa208sha256(key, key.length, 
                passwd, passwd.length,
                salt,
                sodium().crypto_pwhash_opslimit_interactive(),
                sodium().crypto_pwhash_memlimit_interactive());
        
        logger.info("crypto_pwhash_scryptsalsa208sha256 returned: " + rc);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_pwhash_scryptsalsa208sha256() failed, returned " + rc + ", expected 0");
        }
        return key;
    }
    
    public static byte[] cryptoPwhashScryptSalsa208Sha256(byte[] passwd, byte[] salt,
            Long opsLimit,
            NativeLong memLimit) throws SodiumLibraryException
    {
           long salt_length = sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
        if (salt.length != salt_length)
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + salt_length + " bytes");
        }
        byte[] key = new byte[(int) sodium().crypto_box_seedbytes()];
        int rc = sodium().crypto_pwhash_scryptsalsa208sha256(key, key.length, 
                passwd, passwd.length,
                salt,
                opsLimit, memLimit);
        
        logger.info("crypto_pwhash_scryptsalsa208sha256 returned: " + rc);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_pwhash_scryptsalsa208sha256() failed, returned " + rc + ", expected 0");
        }
        return key;

    }
    
    /**
     * Encrypts a message with a key and a nonce
     *
     * @param message message bytes to encrypt
     * @param nonce  nonce bytes. Generate it by calling  {@link cryptoBoxNonceBytes()}
     *
     * @return Encrypted cipher text bytes 
     */  
    public static byte[] cryptoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        long nonce_length = sodium().crypto_secretbox_noncebytes();
        if (nonce_length != nonce.length)
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + ", it must be" + nonce_length + " bytes");
        }
        byte[] cipherText = new byte[(int) (sodium().crypto_box_macbytes() + message.length)];

        int rc = sodium().crypto_secretbox_easy(cipherText,message,message.length,nonce,key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_secretbox_easy() failed, returned " + rc + ", expected 0");
        }
        return cipherText;
    }
    
    public static byte[] cryptoSecretBoxOpenEasy(byte[] cipherText,byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }

        if (nonce.length != sodium().crypto_secretbox_noncebytes())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }

        byte[] decrypted = new byte[(int) (cipherText.length - sodium().crypto_box_macbytes())];
        int rc = sodium().crypto_secretbox_open_easy(decrypted,cipherText,cipherText.length,nonce,key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_secretbox_open_easy() failed, returned " + rc + ", expected 0");
        }
        return decrypted;
    }
    /*
        int crypto_secretbox_detached(byte[] cipherText,
                byte[] mac,
                byte[] message, long mlen,
                byte[] nonce, byte[] key);

    */
    public static SodiumSecretBox cryptoSecretBoxDetached(byte[] message, byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }


        if (nonce.length != sodium().crypto_secretbox_noncebytes())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[(int) sodium().crypto_secretbox_macbytes()];
        
        int rc = sodium().crypto_secretbox_detached(cipherText,mac,message,message.length,nonce,key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_secretbox_detached() failed, returned " + rc + ", expected 0");
        }
        SodiumSecretBox secretBox = new SodiumSecretBox();
        secretBox.setCipherText(cipherText);
        secretBox.setMac(mac);

        return secretBox;
    }
    /*
        int crypto_secretbox_open_detached(byte[] message,
                byte[] cipherText, byte[] mac, long cipherTextLength,
                byte[] nonce, byte[] key);
                */
    
    public static byte[] cryptoSecretBoxOpenDetached(SodiumSecretBox secretBox,
            byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }

        if (nonce.length != sodium().crypto_secretbox_noncebytes())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }
        byte[] mac = secretBox.getMac();
        if (mac.length != sodium().crypto_secretbox_macbytes())
        {
            throw new SodiumLibraryException("invalid mac length " + mac.length + " bytes");
        }

        byte[] message = new byte[secretBox.getCipherText().length];
        byte[] cipherText = secretBox.getCipherText();

        int rc = sodium().crypto_secretbox_open_detached(message,cipherText,mac,cipherText.length,nonce,key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_secretbox_open_detached() failed, returned " + rc + ", expected 0");
        }
        return message;
    }
    
    public static byte[] cryptoAuth(byte[] message, byte[] key) throws SodiumLibraryException
    {
        byte[] mac = new byte[(int) sodium().crypto_auth_bytes()];

        long keySize = sodium().crypto_auth_keybytes();
        if (key.length != keySize)
        {
            throw new SodiumLibraryException("Expected key size " + keySize + " bytes, but passed " + key.length + " bytes");
        }
        int rc = sodium().crypto_auth(mac, message, message.length, key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_auth() failed, returned " + rc + ", expected 0");
        }
        return  mac;
    }
    
    public static boolean cryptoAuthVerify(byte[] mac, byte[] message, byte[] key) throws SodiumLibraryException
    {
        long keySize = sodium().crypto_auth_keybytes();
        if (key.length != keySize)
        {
            throw new SodiumLibraryException("Expected key size " + keySize + " bytes, but passed " + key.length + " bytes");
        }
        int rc = sodium().crypto_auth_verify(mac, message, message.length, key);
        if (rc == 0)
        {
            return true;
        }
        else if(rc == -1)
        {
            return false;
        }

        return false;
    }
    
    
    public static SodiumKeyPair cryptoBoxKeyPair() throws SodiumLibraryException
    {
        SodiumKeyPair kp = new SodiumKeyPair();
        byte[] publicKey = new byte[(int) sodium().crypto_box_publickeybytes()];
        byte[] privateKey = new byte[(int) sodium().crypto_box_secretkeybytes()];
        int rc = sodium().crypto_box_keypair(publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_keypair() failed, returned " + rc + ", expected 0");
        }
        kp.setPublicKey(publicKey);
        kp.setPrivateKey(privateKey);
        logger.info("pk len: " + publicKey.length);
        logger.info("sk len: " + privateKey.length);
        return kp;
    }
    
    public static byte[] cryptoPublicKey(byte[] privateKey) throws SodiumLibraryException
    {
        byte[] publicKey = new byte[(int) sodium().crypto_box_publickeybytes()];
        int rc = sodium().crypto_scalarmult_base(publicKey,privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_scalrmult() failed, returned " + rc + ", expected 0");
        }
        return publicKey;
    }
    
    public static long cryptoBoxNonceBytes()
    {
        return sodium().crypto_box_noncebytes();
    }
    
    public static long crytoBoxSeedBytes()
    {
        return sodium().crypto_box_seedbytes();
    }
    
    public static long crytoBoxPublicKeyBytes()
    {
        return sodium().crypto_box_publickeybytes();
    }
    
    public static long crytoBoxSecretKeyBytes()
    {
       return sodium().crypto_box_secretkeybytes();
    }
    
    public static long cryptoBoxMacBytes()
    {
        return sodium().crypto_box_macbytes();
    }
    
    public static long cryptoBoxSealBytes()
    {
        return sodium().crypto_box_sealbytes();
    }
    
    /* secret-key */
    public static long cryptoSecretBoxKeyBytes()
    {
        return sodium().crypto_secretbox_keybytes();
    }
    
    public static long cryptoSecretBoxNonceBytes()
    {
       return sodium().crypto_secretbox_noncebytes();
    }
    
    public static long cryptoSecretBoxMacBytes()
    {
        return sodium().crypto_secretbox_macbytes();        
    }

   /**
    * @return number of salt bytes
    * <p>
    * @author muquit@muquit.com - Jan 1, 2017
    */
    public static int cryptoNumberSaltBytes()
    {
        return sodium().crypto_pwhash_saltbytes();
    }
    
    public static int cryptoPwhashAlgArgon2i13()
    {
        return sodium().crypto_pwhash_alg_argon2i13();
    }
    
    public static int cryptoPwhashAlgDefault()
    {
        return sodium().crypto_pwhash_alg_default();
    }

    public static int cryptoPwhashSaltBytes()
    {
        return sodium().crypto_pwhash_saltbytes();
    }
    
    public static long cryptoPwHashOpsLimitInteractive()
    {
        return sodium().crypto_pwhash_opslimit_interactive();
    }
    
    public static NativeLong cryptoPwHashMemLimitInterative()
    {
        return sodium().crypto_pwhash_memlimit_interactive();
    }
    
    public static long cryptoPwHashScryptSalsa208Sha256SaltBytes()
    {
        return sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
    }

    
    public static byte[] cryptoBoxEasy(byte[] message, byte[] nonce,
            byte[] publicKey, byte[] privateKey) throws SodiumLibraryException
    {
        long nonce_len = sodium().crypto_box_noncebytes();
        if (nonce.length != nonce_len)
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + "bytes, it must be" + nonce_len + " bytes");
        }
        byte[] cipherText = new byte[(int) (sodium().crypto_box_macbytes() + message.length)];
        int rc = sodium().crypto_box_easy(cipherText,
                message,message.length,
                nonce,
                publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_easy() failed, returned " + rc + ", expected 0");
        }

        return cipherText;
    }
    
    public static byte[] cryptoBoxOpenEasy(byte[] cipherText, byte[]nonce, 
            byte[] publicKey, byte[] privateKey) throws SodiumLibraryException
    {
        long nonce_len = sodium().crypto_box_noncebytes();
        if (nonce.length != nonce_len)
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + "bytes, it must be" + nonce_len + " bytes");
        }
        byte[] decrypted = new byte[(int) (cipherText.length - sodium().crypto_box_macbytes())];
        int rc = sodium().crypto_box_open_easy(decrypted, cipherText, 
                cipherText.length, nonce, 
                publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_open_easy() failed, returned " + rc + ", expected 0");
        }
        
        return decrypted;
    }
    
    public static byte[] cryptoBoxSeal(byte[] message, byte[] recipientPublicKey) throws SodiumLibraryException
    {
        logger.info("message len: " + message.length);
//        byte[] cipherText = new byte[62]; // WTF is that??
        byte[] cipherText = new byte[(int) (sodium().crypto_box_sealbytes() + message.length)];
        int rc = sodium().crypto_box_seal(cipherText, message, message.length, recipientPublicKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_seal() failed, returned " + rc + ", expected 0");
        }
        return cipherText;
    }
    
    public static byte[] cryptoBoxSealOpen(byte[] cipherText,byte[] pk, byte[] sk) throws SodiumLibraryException
    {
        byte[] decrypted = new byte[(int) (cipherText.length - sodium().crypto_box_sealbytes())];
        int rc = sodium().crypto_box_seal_open(decrypted, cipherText, cipherText.length, pk, sk);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_seal_open() failed, returned " + rc + ", expected 0");
        }
        return decrypted;
        
    }
    ////////////////////
}
