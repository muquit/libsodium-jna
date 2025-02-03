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
 * SodiumLibrary is a Java binding to <a href="https://download.libsodium.org/doc/" target="_blank">libsodium</a> crypto C APIs 
 * using <a href="https://github.com/java-native-access/jna" target="_blank">Java Native Access</a>.
 * All the methods are
 * static methods. Most methods throw {@link com.muquit.libsodiumjna.exceptions.SodiumLibraryException} at run time
 * in case of errors.
 * <p> 
 * Please look at <a href="https://github.com/muquit/libsodium-jna/" target="_blank">libsodium-jna Homepage</a> for
 * instructions on how to get started.
 * </p>
 * 
 * @see <a href="https://download.libsodium.org/doc/" target="_blank">Native libsodium</a> documentation
 * <a href="https://github.com/muquit/libsodium-jna/" target="_blank">libsodium-jna Homepage</a>
 */
public class SodiumLibrary
{
    private final static Logger logger = LoggerFactory.getLogger(SodiumLibrary.class);
    
    private static String libPath;
    private static boolean initialized = false;

    private SodiumLibrary(){}
    
    public static void log(String msg)
    {
        System.out.println("MMMM: " + msg);
    }
    
   /**
    * Set the absolute path of the libsodium shared library/DLL.
    *<p> 
    * This method 
    * <b><font color="red">must</font></b> be called before calling any methods in libsodium-jna. Although JNA supports loading
    * a shared library from path, libsodium-jna requires specifying the absolute
    * path to make sure that the exact library is being loaded.
    * For example, in Linux, it might be /usr/local/lib/libsodium.so, in Windows, 
    * it might be c:/libs/libsodium.dll, in MacOS, it might be 
    * /usr/local/lib/libsodium.dylib etc. The point is there is no
    * ambiguity, I want to load the library I want, not one from somewhere in the path. 
    * </p>
    * @param libraryPath The absolute path of the libsodium library. 
    * <h3>Example</h3>
    * <pre>
    * <code>
    * private static String libraryPath = null;
    *
    * if (Platform.isMac())
    * {
    *     // MacOS
    *     libraryPath = "/usr/local/lib/libsodium.dylib";
    *     libraryPath = libraryPath;
    *     logger.info("Library path in Mac: " + libraryPath);
    * }
    * else if (Platform.isWindows())
    * {
    *     // Windows
    *     libraryPath = "C:/libsodium/libsodium.dll";
    *     logger.info("Library path in Windows: " + libraryPath);
    * }
    * else
    * {
    *     // Linux
    *     libraryPath = "/usr/local/lib/libsodium.so";
    *     logger.info("Library path: " + libraryPath);
    * }
    * 
    * logger.info("loading libsodium...");
    * SodiumLibrary.setLibraryPath(libraryPath);
    * // To check the native library is actually loaded, print the version of 
    * // native sodium library
    * String v = SodiumLibrary.libsodiumVersionString();
    * logger.info("libsodium version: " + v);
    * </code>
    * </pre>
    */
    public static void setLibraryPath(String libraryPath)
    {
        SodiumLibrary.libPath = libraryPath;
    }
    
    /**
     * @return path of library set by SodiumLibary.setLibraryPath()
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
     * </p>
     * @throws RuntimeException at run time if the libsodium library path 
     * is not set by calling {@link SodiumLibrary#setLibraryPath(String)}
     */
    public static Sodium sodium()
    {
        if (SodiumLibrary.libPath == null)
        {
            logger.info("libpath not set, throw exception");
            throw new RuntimeException("Please set the absolute path of the libsodium libary by calling SodiumLibrary.setLibraryPath(path)");
        }

        final Sodium sodium = SingletonHelper.instance;
        
        if (!initialized) {
        	int rc = sodium.sodium_init();
        	if (rc == -1)
        	{
        		logger.error("ERROR: sodium_init() failed: " + rc);
        		throw new RuntimeException("sodium_init() failed, rc=" + rc);
        	}
        	initialized = true;
        }
        return sodium;
    }

    private static final class SingletonHelper
    {
        public static final Sodium instance = (Sodium) Native.loadLibrary(libPath,Sodium.class);
    }

    /**
     * Declare all the supported <a href="https://download.libsodium.org/doc/" target="_blank">libsodium</a> C functions in this interface and 
     * implement them in this class as static methods.
     * 
     */
    public interface Sodium extends Library
    {
        int sodium_library_version_major();
        int sodium_library_version_minor();
        int sodium_init();

        /*
         * @return version string of the libsodium library
         * include/sodium/version.h
         */
        String sodium_version_string();
        
        /*
         * Fills size bytes starting at buf with an unpredictable sequence of bytes.
         * @param buf  buffer to fill with random bytes
         * @param size number of random bytes
         * <a href="https://download.libsodium.org/doc/generating_random_data/">Generating random data</a> libsodium page
         */
        void randombytes_buf(byte[] buf, int size);

        /*
         * see include/sodium/crypto_pwhash.h
         */
        int crypto_pwhash_alg_argon2i13();
        int crypto_pwhash_alg_argon2id13(); // added in libsodium 1.0.15
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
        NativeLong crypto_box_seedbytes();
        NativeLong crypto_box_publickeybytes();
        NativeLong crypto_box_secretkeybytes();
        NativeLong crypto_box_noncebytes();
        NativeLong crypto_box_macbytes();
        NativeLong crypto_box_sealbytes();

        /* sodium/crypto_auth.h */
        NativeLong crypto_auth_bytes();
        NativeLong crypto_auth_keybytes();
        
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
        NativeLong crypto_pwhash_scryptsalsa208sha256_saltbytes();
        
        /* Secret Key */
        NativeLong  crypto_secretbox_keybytes();
        NativeLong  crypto_secretbox_noncebytes();
        NativeLong  crypto_secretbox_macbytes();        
        
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
        
        int crypto_scalarmult(byte[] q, byte[] n, byte[] p);
       /**
        * Compute Public key from Private Key
        * @param pk - Public Key returns
        * @param sk - Private Key
        * @return 0 on success -1 on failure
        */
        int crypto_scalarmult_base(byte[] pk, byte[] sk);
        
        int crypto_box_easy(byte[] cipher_text,
                byte[] plain_text, long pt_len,
                byte[] nonce,
                byte[] public_key, byte[] private_key);

        int crypto_box_open_easy(byte[] decrypted, byte[] cipher_text,
                long ct_len, byte[] nonce,
                byte[] public_key, byte[] private_key);

        // Signing/Signed keys
        long crypto_sign_secretkeybytes();
        long crypto_sign_publickeybytes();
        int crypto_sign_keypair(byte[] pk, byte[] sk);
        int crypto_sign_seed_keypair(byte[] pk, byte[] sk, byte[] seed);
        int crypto_sign_ed25519_bytes();
        int crypto_sign_bytes();
        
        // actual signing and verification operations of the Signing key, first detached mode, then combined mode
        int crypto_sign_detached(byte[] sig, long siglen_p,
        						byte[]  m, long mlen,
        						byte[] sk);
        
        int crypto_sign_verify_detached(byte[] sig, byte[] m,
                                    	long mlen, byte[] pk);
        
        int crypto_sign(byte[] sm, long smlen_p,
        				byte[] m, long mlen,
        				byte[] sk);
        
        int crypto_sign_open(byte[] m, long mlen_p,
        					byte[] sm, long smlen,
        					byte[] pk);

        
        // libsodium's generichash (blake2b), this function will only return outlen number of bytes
        // key can be null and keylen can be 0
        int crypto_generichash(byte[] out, int outlen,
        		byte[] in, int inlen,
        		byte[] key, long keylen);
        
        // key conversion from ED to Curve so that signed key can be used for encryption
        int crypto_sign_ed25519_sk_to_curve25519(byte[] curveSK, byte[] edSK); // secret key conversion
        int crypto_sign_ed25519_pk_to_curve25519(byte[] curvePK, byte[] edPK); // public key conversion
    
    }

    ////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////

    public static byte[] cryptoSignOpen(byte[] sig, byte[] pk) throws SodiumLibraryException
    {
    	byte[] m = new byte[(int) sig.length];
    	byte[] mlen = new byte[1];
        int rc = sodium().crypto_sign_open(m, mlen[0], sig, (long) sig.length, pk);
        if (rc == 0) { return m; }
        return new byte[1];
    }
    
    public static byte[] cryptoSign(byte[] m, byte[] sk) throws SodiumLibraryException
    {
        byte[] sm = new byte[sodium().crypto_sign_bytes()+m.length];
        byte[] test = new byte[1];
        int rc = sodium().crypto_sign(sm, test[0], m, m.length, sk);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_sign (combined mode, not detached) failed, returned " + rc + ", expected 0");
        }
        return sm;
    }
    
    public static boolean cryptoSignVerifyDetached(byte[] sig, byte[] msg, byte[] pk) throws SodiumLibraryException
    {
        int rc = sodium().crypto_sign_verify_detached(sig, msg, (long) msg.length, pk);
        if (rc == 0) { return true; }
        if (rc == -1) { return false; }
        throw new SodiumLibraryException("libsodium crypto_sign_verify_detached failed, returned " + rc + ", expected 0 (a match) or -1 (mismatched)");
    }
    
    public static byte[] cryptoSignDetached(byte[] msg, byte[] sk) throws SodiumLibraryException
    {
        byte[] sig = new byte[sodium().crypto_sign_ed25519_bytes()];
        int rc = sodium().crypto_sign_detached(sig, 0L, msg, msg.length, sk);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_sign_detached failed, returned " + rc + ", expected 0");
        }
        return sig;
    }
    
   
    
    //implementation of Sodium's public key / secret key signing.
    // a SodiumKeyPair is created and returned containing the secret signing key and the public key
    // that has been signed by the private key. the secret key (64 bytes) is simply
    // the 32 byte random seed that Sodium generated + the 32byte public key that was signed by the private key
    public static SodiumKeyPair cryptoSignKeyPair() throws SodiumLibraryException
    {
        SodiumKeyPair kp = new SodiumKeyPair();
        byte[] publicKey = new byte[(int) sodium().crypto_sign_publickeybytes()];
        byte[] privateKey = new byte[(int) sodium().crypto_sign_secretkeybytes()];
        int rc = sodium().crypto_sign_keypair(publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_sign_keypair() failed, returned " + rc + ", expected 0");
        }
        kp.setPublicKey(publicKey);
        kp.setPrivateKey(privateKey);
        if (logger.isDebugEnabled()) {
            logger.debug("pk len: " + publicKey.length);
            logger.debug("sk len: " + privateKey.length);
        }
        return kp;
    }
    
    public static SodiumKeyPair cryptoSignSeedKeyPair(byte[] seed32) throws SodiumLibraryException
    {
        SodiumKeyPair kp = new SodiumKeyPair();
        byte[] publicKey = new byte[(int) sodium().crypto_sign_publickeybytes()];
        byte[] privateKey = new byte[(int) sodium().crypto_sign_secretkeybytes()];
        int rc = sodium().crypto_sign_seed_keypair(publicKey, privateKey, seed32);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_sign_seed_keypair() failed, returned " + rc + ", expected 0");
        }
        kp.setPublicKey(publicKey);
        kp.setPrivateKey(privateKey);
        if (logger.isDebugEnabled()) {
            logger.debug("pk len: " + publicKey.length);
            logger.debug("sk len: " + privateKey.length);
        }
        return kp;
    }
    
    // libsodium's generichash (blake2b), this function will only return 'length' number of bytes of the hash
    // this implementation does not expect key/key.length which blake does need, so we are setting them to null and 0
    public static byte[] cryptoGenerichash(byte[] input, int length) throws SodiumLibraryException
    {
        byte[] hash = new byte[length];
        int rc = sodium().crypto_generichash(hash, length, input, input.length, null, 0);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_generichash failed, returned " + rc + ", expected 0");
        }
        return hash;
    }
    
    // key conversion from ED to Curve so that signed public key can be used for encryption - secret key conversion
    public static byte[]cryptoSignEdSkTOcurveSk (byte[] edSK)  throws SodiumLibraryException {
    	byte[] curveSK = new byte[sodium().crypto_box_publickeybytes().intValue()];
    	int rc = sodium().crypto_sign_ed25519_sk_to_curve25519(curveSK, edSK);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_generichash failed, returned " + rc + ", expected 0");
        }   	
    	return curveSK;    	
    }
    
    // key conversion from ED to Curve so that signed public key can be used for encryption - secret key conversion
    public static byte[]cryptoSignEdPkTOcurvePk (byte[] edPK)  throws SodiumLibraryException {
    	byte[] curvePK = new byte[sodium().crypto_box_publickeybytes().intValue()];
    	int rc = sodium().crypto_sign_ed25519_pk_to_curve25519(curvePK, edPK);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_generichash failed, returned " + rc + ", expected 0");
        }   	
    	return curvePK;    	
    }


    /**
     * @return version string of libsodium
     */
    public static String libsodiumVersionString()
    {
        return sodium().sodium_version_string();
    }
    
    
   /**
    * Return unpredictable sequence of bytes.
    * 
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
    * @param  size Number of random bytes to generate
    * @return Array of random bytes
    * @see <a href="https://download.libsodium.org/doc/generating_random_data/" target="_blank">Generating random data</a> in libsodium page
    * <h3>Example</h3>
    * <pre>
    * <code>
    * // generate 16 bytes of random data
    * byte[] randomBytes = SodiumLibrary.randomBytes(16);
    * String hex = SodiumUtils.binary2Hex(salt);
    * 
    * // generate libsodium's standard number of salt bytes
    * int n = SodiumLibrary.cryptoNumberSaltBytes();
    * logger.info("Generate " + n + " random bytes");
    * 
    * byte[] salt = SodiumLibrary.randomBytes(n);
    * logger.info("Generated " + salt.length + " random bytes");
    * String hex = SodiumUtils.binary2Hex(salt);
    * logger.info("Random bytes: " + hex);
    * </code>
    * </pre>
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

    public static byte[] cryptoPwhashArgon2idInteractive(byte[] passwd, byte[] salt16)
            throws SodiumLibraryException {
        int outBytesLength = cryptoBoxSeedBytes().intValue();
        return cryptoPwhashArgon2idInteractive(passwd, salt16, outBytesLength);
    }

    public static byte[] cryptoPwhashArgon2idInteractive(byte[] passwd, byte[] salt16, int outBytesLength)
            throws SodiumLibraryException {
        long opsLimit = cryptoPwHashOpsLimitInteractive();
        NativeLong memLimit = cryptoPwHashMemLimitInterative();
        return cryptoPwhash(passwd, salt16, outBytesLength, opsLimit, memLimit, cryptoPwhashAlgArgon2id13());
    }
    
    public static byte[] cryptoPwhash(byte[] passwd, byte[] salt16, long opsLimit, NativeLong memLimit, int algorithm)
            throws SodiumLibraryException {
        int outBytesLength = cryptoBoxSeedBytes().intValue();
        return cryptoPwhash(passwd, salt16, outBytesLength, opsLimit, memLimit, algorithm);
    }

    public static byte[] cryptoPwhash(byte[] passwd, byte[] salt16, int outBytesLength, long opsLimit,
            NativeLong memLimit, int algorithm) throws SodiumLibraryException {
        byte[] key = new byte[outBytesLength];

        int rc = sodium().crypto_pwhash(key, key.length, 
                passwd, passwd.length,
                salt16,
                opsLimit,
                memLimit,
                algorithm);

        if (logger.isDebugEnabled()) {
            logger.debug(">>> NativeLong size: " + NativeLong.SIZE * 8 + " bits");
            logger.debug("crypto_pwhash returned: " + rc);
        }

        if (rc != 0)
        {
            throw new SodiumLibraryException("cryptoPwhash libsodium crypto_pwhash failed, returned " + rc + ", expected 0");
        }
        return key;

    }
    
    /**
     * Derive a key using Argon2id password hashing scheme
     * <p>
     * The following is taken from <a href="https://download.libsodium.org/doc/password_hashing/">libsodium documentation</a>:
     * <blockquote>
     * Argon2 is optimized for the x86 architecture and exploits the cache and memory organization of the recent Intel 
     * and AMD processors. But its implementation remains portable and fast on other architectures. Argon2 has three 
     * variants: Argon2d, Argon2i and Argon2id. Argon2i uses data-independent memory access, which is preferred for 
     * password hashing and password-based key derivation. Argon2i also makes multiple passes over the memory to 
     * protect from tradeoff attacks. Argon2id combines both.

     * </blockquote>
     * 
     * @param passwd Array of bytes of password
     * @param salt Salt to use in key generation. The salt should be unpredictable and can be generated by calling SodiumLibary.randomBytes(int)
     * The salt should be saved by the caller as it will be needed to derive the key again from the 
     * password.
     * @return Generated key as an array of bytes
     * @throws SodiumLibraryException if libsodium's crypto_pwhash() does not return 0
     * <code>crypto_pwhash()</code> in <a href="https://download.libsodium.org/doc/password_hashing/">Password hashing</a>
     * libsodium page. <a href="https://github.com/P-H-C/phc-winner-argon2/raw/master/argon2-specs.pdf">Argon2i v1.3 Algorithm</a>. 
     * <h3>Example</h3>
     * <pre>
     * <code>
     * String password = "This is a Secret";
     * salt = SodiumLibary.randomBytes(sodium().crypto_pwhash_saltbytes());
     * byte[] key = SodiumLibary.cryptoPwhashArgon2i(password.getBytes(),salt);
     * String keyHex = SodiumUtils.bin2hex(key);
     </code>
     *</pre>
     */
    public static byte[] cryptoPwhashArgon2i(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        int saltLength = cryptoPwhashSaltBytes();
        if (salt.length != saltLength)
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + saltLength + " bytes");
        }

        byte[] key = new byte[sodium().crypto_box_seedbytes().intValue()];
        
        int rc = sodium().crypto_pwhash(key, key.length, 
                passwd, passwd.length,
                salt,
                sodium().crypto_pwhash_opslimit_interactive(),
                sodium().crypto_pwhash_memlimit_interactive(),
                sodium().crypto_pwhash_alg_argon2id13());

        if (logger.isDebugEnabled()) {
            logger.debug(">>> NavtiveLong size: " + NativeLong.SIZE * 8 + " bits");
            logger.debug(">>> opslimit: " + sodium().crypto_pwhash_opslimit_interactive());
            logger.debug(">>> memlimit: " +  sodium().crypto_pwhash_memlimit_interactive());
//        logger.debug(">>> alg: " +  sodium().crypto_pwhash_alg_argon2i13());
            logger.debug(">>> alg: " +  sodium().crypto_pwhash_alg_argon2id13()); // libsodium 1.0.15
            logger.debug("crypto_pwhash returned: " + rc);
        }

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
     * @throws SodiumLibraryException on error
     */
    public static byte[] deriveKey(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        return cryptoPwhashArgon2i(passwd, salt);
    }
    
   /**
    * Returns a US-ASCII encoded key derived from the password.
    * 
    * The key can be stored for verification. Memory-hard, CPU-intensive hash function is applied to the  
    * password in key generation process. Automatically generated salt is used in the key generation
    * Uses opslimit as <code>crypto_pwhash_opslimit_interactive()</code> and memlimit as 
    * <code>crypto_pwhash_memlimit_interactive()</code>
    * @param password The password 
    * @throws SodiumLibraryException on error
    * @return derived key as US-ASCII encoded string
    * <h3>Example</h3>
    * <pre>
    * <code>
    *  String password = new String("বাংলা");
    *  // convert to UTF-8 encoded bytes
    *  byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8); // requires jdk 1.7+
    *  String key = SodiumLibrary.cryptoPwhashStr(passwordBytes);
    * </code>
    * </pre>
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

    /*
     * Verify a US-ASCII encoded key derived previously by calling SodiumLibrary.cryptoPwhashStr(byte[])
     * 
     * @param usAsciiKey key in US ASCII
     * @param password bytes
     * @return true if the key can be verified false otherwise
     */
    
   /**
    * Verify a US-ASCII encoded key derived previously by calling  {@link SodiumLibrary#cryptoPwhashStr(byte[])}
    *  @param usAsciiKey US-ASCII encoded key to verify
    *  @param password The password
    *  @return true if the key can be verified, false otherwise
    *  <h3>Example</h3>
    *  <pre>
    *  <code>
    *  String password = new String("বাংলা");
    * // convert to UTF-8 encoded bytes
    * byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8); // requires jdk 1.7+
    * String key = SodiumLibrary.cryptoPwhashStr(passwordBytes);
    * // verify the password
    * boolean rc = SodiumLibrary.cryptoPwhashStrVerify(key, passwordBytes);
    * if (rc)
    * {
    *   logger.info("Password is verified");
    * }
    *  </code>
    *  </pre>
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
     * Derive key from a password using scrypt.
     * <p>
     * Excerpt from libsodium documentation:
     * <blockquote>
     * Scrypt was also designed to make it costly to perform large-scale custom hardware attacks by requiring large 
     * amounts of memory.
     * <p>
     * Even though its memory hardness can be significantly reduced at the cost of extra computations, this function 
     * remains an excellent choice today, provided that its parameters are properly chosen.
     * </p>
     * Scrypt is available in libsodium since version 0.5.0, which makes it a better choice than Argon2 if compatibility with older libsodium versions is a concern.
     * </blockquote>
     * 
     * @param passwd Array of bytes of password
     * @param salt Salt to use in key generation. The salt should be 
     * unpredictable and can be generated by calling {@link SodiumLibrary#randomBytes(int)}
     * The salt should be saved by the caller as it will be needed to derive the key again from the 
     * password.
     * @return key as an array of bytes
     * @throws SodiumLibraryException on error
     * @see <a href="https://download.libsodium.org/doc/password_hashing/" target="_blank">Password hashing</a>
     */
    public static byte[] cryptoPwhashScrypt(byte[] passwd, byte[] salt) throws SodiumLibraryException
    {
        NativeLong salt_length = sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
        if (salt.length != salt_length.intValue())
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + salt_length + " bytes");
        }
        byte[] key = new byte[sodium().crypto_box_seedbytes().intValue()];
        int rc = sodium().crypto_pwhash_scryptsalsa208sha256(key, key.length, 
                passwd, passwd.length,
                salt,
                sodium().crypto_pwhash_opslimit_interactive(),
                sodium().crypto_pwhash_memlimit_interactive());

        if (logger.isDebugEnabled()) {
            logger.debug("crypto_pwhash_scryptsalsa208sha256 returned: " + rc);
        }

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
        NativeLong salt_length = sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
        if (salt.length != salt_length.intValue())
        {
            throw new SodiumLibraryException("salt is " + salt.length + ", it must be" + salt_length + " bytes");
        }
        byte[] key = new byte[sodium().crypto_box_seedbytes().intValue()];
        int rc = sodium().crypto_pwhash_scryptsalsa208sha256(key, key.length, 
                passwd, passwd.length,
                salt,
                opsLimit, memLimit);

        if (logger.isDebugEnabled()) {
            logger.debug("crypto_pwhash_scryptsalsa208sha256 returned: " + rc);
        }

        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_pwhash_scryptsalsa208sha256() failed, returned " + rc + ", expected 0");
        }
        return key;

    }
    
    /**
     * Encrypts a message with a key and a nonce to keep it confidential.
     * 
     * The same key is used to encrypt and decrypt the messages. Therefore, the key must be kept confidential.
     *
     * @param message message bytes to encrypt
     * @param nonce  nonce bytes. The nonce must be {@link SodiumLibrary#cryptoBoxNonceBytes()} bytes long and can be generated by
     * calling {@link SodiumLibrary#randomBytes(int)}
     * @param key They key for encryption
     * @throws SodiumLibraryException on error
     * @return Encrypted cipher text bytes 
     * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/authenticated_encryption.html" target="_blank">Secret-key authenticated encryption</a>
     */  
    public static byte[] cryptoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        int nonce_length = sodium().crypto_secretbox_noncebytes().intValue();
        if (nonce_length != nonce.length)
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + ", it must be" + nonce_length + " bytes");
        }
        byte[] cipherText = new byte[(sodium().crypto_box_macbytes().intValue() + message.length)];

        int rc = sodium().crypto_secretbox_easy(cipherText,message,message.length,nonce,key);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_secretbox_easy() failed, returned " + rc + ", expected 0");
        }
        return cipherText;
    }
    
   /**
    * Verifies and decrypts a ciphertext.
    * 
    *  The ciphertext is created by {@link SodiumLibrary#cryptoSecretBoxEasy(byte[] message, byte[] nonce, byte[] key)}
    * 
    * @param cipherText The ciphertext to decrypt
    * @param nonce The nonce used during encryption
    * @param key The key used in encryption
    * @return decrypted plaintext bytes
    * @throws SodiumLibraryException - if nonce size is incorrect or decryption fails
    * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/authenticated_encryption.html" target="_blank">Secret-key authenticated encryption</a>
    * <h3>Example</h3>
    * <pre>
    * <code>
    * // don't forget to load the libsodium library first
    * String message = "This is a message";
    * 
    * // generate nonce
    * long nonceBytesLength = SodiumLibrary.cryptoSecretBoxNonceBytes();
    * byte[] nonceBytes = SodiumLibrary.randomBytes((int) nonceBytesLength);
    * byte[] messageBytes = message.getBytes();
    *
    * // generate the encryption key
    * byte[] key = SodiumLibrary.randomBytes((int) SodiumLibrary.cryptoSecretBoxKeyBytes());
    * 
    * // encrypt
    * byte[] cipherText = SodiumLibrary.cryptoSecretBoxEasy(messageBytes, nonceBytes, key);
    *
    * // now decrypt
    * byte[] decryptedMessageBytes = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText, nonceBytes, key);
    * String decryptedMessage;
    * try
    * {
    *    decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
    *    System.out.println("Decrypted message: " + decryptedMessageBytes);
    * } catch (UnsupportedEncodingException e)
    * {
    *    e.printStackTrace();
    * }
    * </code>
    * </pre>
    */
    public static byte[] cryptoSecretBoxOpenEasy(byte[] cipherText,byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes().intValue())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }

        if (nonce.length != sodium().crypto_secretbox_noncebytes().intValue())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }

        byte[] decrypted = new byte[(cipherText.length - sodium().crypto_box_macbytes().intValue())];
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
    
   /**
    * Encrypts a message with a key and a nonce to keep it confidential - detached mode.
    * 
    * @param message The message bytes to encrypt
    * @param nonce The nonce to use in encryption
    * @param key The key to encrypt
    * @return {@link SodiumSecretBox}
    * @throws SodiumLibraryException on error
    * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/authenticated_encryption.html" target="_blank">Secret-key authenticated encryption</a>
    */
    public static SodiumSecretBox cryptoSecretBoxDetached(byte[] message, byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes().intValue())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }


        if (nonce.length != sodium().crypto_secretbox_noncebytes().intValue())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }
        byte[] cipherText = new byte[message.length];
        byte[] mac = new byte[(int) sodium().crypto_secretbox_macbytes().intValue()];
        
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
    
   /**
    * Verifies and decrypts a ciphertext - detached mode
    * 
    * @param secretBox {@link SodiumSecretBox} used during encryption
    * @param nonce Nonce used in encryption
    * @param key The key used in encryption
    * @return decrypted plaintext bytes
    * @throws SodiumLibraryException on error
    * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/authenticated_encryption.html" target="_blank">Secret-key authenticated encryption</a>
    */
    public static byte[] cryptoSecretBoxOpenDetached(SodiumSecretBox secretBox,
            byte[] nonce, byte[] key) throws SodiumLibraryException
    {
        if (key.length != sodium().crypto_secretbox_keybytes().intValue())
        {
            throw new SodiumLibraryException("invalid key length " + key.length + " bytes");
        }

        if (nonce.length != sodium().crypto_secretbox_noncebytes().intValue())
        {
            throw new SodiumLibraryException("invalid nonce length " + nonce.length + " bytes");
        }
        byte[] mac = secretBox.getMac();
        if (mac.length != sodium().crypto_secretbox_macbytes().intValue())
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
    
    /**
     * Computes an authentication tag for a message with a secret key. 
     * 
     * The operation does not encrypt the message. 
     * Usage: Alice prepares a message and the authentication tag and send it to Bob. Alice does not store the message. Later
     * Bob sends the message and the authentication tag to Alice. Alice calls {@link SodiumLibrary#cryptoAuthVerify(byte[] mac, byte[] message, byte[] key)}
     * verify that the message is created by her.
     * 
     * @param message Computes the tag for this message bytes
     * @param key The secret key. The key size must be crypto_auth_keybytes() long
     * @return Authentication tag bytes
     * @throws SodiumLibraryException on error
     * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/secret-key_authentication.html" target="_blank">Secret-key authentication</a>
     */
    public static byte[] cryptoAuth(byte[] message, byte[] key) throws SodiumLibraryException
    {
        byte[] mac = new byte[sodium().crypto_auth_bytes().intValue()];

        int keySize = sodium().crypto_auth_keybytes().intValue();
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
    
    /**
     * Verify message authentication code with the secret key
     * 
     * @param mac Message authentication code
     * @param message The message
     * @param key The secret key used to create the authentication code
     * @return true or false
     * @throws SodiumLibraryException on error
     * @see <a href="https://download.libsodium.org/libsodium/content/secret-key_cryptography/secret-key_authentication.html" target="_blank">Secret-key authentication</a>
     */
    public static boolean cryptoAuthVerify(byte[] mac, byte[] message, byte[] key) throws SodiumLibraryException
    {
        int keySize = sodium().crypto_auth_keybytes().intValue();
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
    
    
    /**
     * Randomly generates a private key and the corresponding public key
     * 
     * @return {@link SodiumKeyPair}
     * @throws SodiumLibraryException on error
     * @see <a href="https://download.libsodium.org/libsodium/content/public-key_cryptography/authenticated_encryption.html" target="_blank">Public-key authenticated encryption</a>
     */
    public static SodiumKeyPair cryptoBoxKeyPair() throws SodiumLibraryException
    {
        SodiumKeyPair kp = new SodiumKeyPair();
        byte[] publicKey = new byte[sodium().crypto_box_publickeybytes().intValue()];
        byte[] privateKey = new byte[sodium().crypto_box_secretkeybytes().intValue()];
        int rc = sodium().crypto_box_keypair(publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_keypair() failed, returned " + rc + ", expected 0");
        }
        kp.setPublicKey(publicKey);
        kp.setPrivateKey(privateKey);

        if (logger.isDebugEnabled()) {
            logger.debug("pk len: " + publicKey.length);
            logger.debug("sk len: " + privateKey.length);
        }

        return kp;
    }
    
    /**
     * Given a private key, generate the corresponding public key
     * @param privateKey The private key
     * @throws SodiumLibraryException on error
     * @return public key bytes
     */
    public static byte[] cryptoPublicKey(byte[] privateKey) throws SodiumLibraryException
    {
        byte[] publicKey = new byte[sodium().crypto_box_publickeybytes().intValue()];
        int rc = sodium().crypto_scalarmult_base(publicKey,privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_scalrmult() failed, returned " + rc + ", expected 0");
        }
        return publicKey;
    }
    
    public static NativeLong cryptoBoxNonceBytes()
    {
        return sodium().crypto_box_noncebytes();
    }
    
    public static NativeLong cryptoBoxSeedBytes()
    {
        return sodium().crypto_box_seedbytes();
    }
    
    public static NativeLong cryptoBoxPublicKeyBytes()
    {
        return sodium().crypto_box_publickeybytes();
    }
    
    public static NativeLong cryptoBoxSecretKeyBytes()
    {
       return sodium().crypto_box_secretkeybytes();
    }
    
    public static NativeLong cryptoBoxMacBytes()
    {
        return sodium().crypto_box_macbytes();
    }
    
    public static NativeLong cryptoBoxSealBytes()
    {
        return sodium().crypto_box_sealbytes();
    }
    
    /* secret-key */
    public static NativeLong cryptoSecretBoxKeyBytes()
    {
        return sodium().crypto_secretbox_keybytes();
    }
    
    public static NativeLong cryptoSecretBoxNonceBytes()
    {
       return sodium().crypto_secretbox_noncebytes();
    }
    
    public static NativeLong cryptoSecretBoxMacBytes()
    {
        return sodium().crypto_secretbox_macbytes();        
    }

   /*
    * @return number of salt bytes
    */
    public static int cryptoNumberSaltBytes()
    {
        return sodium().crypto_pwhash_saltbytes();
    }
    
    public static int cryptoPwhashAlgArgon2i13()
    {
        return sodium().crypto_pwhash_alg_argon2i13();
    }

    public static int cryptoPwhashAlgArgon2id13()
    {
        return sodium().crypto_pwhash_alg_argon2id13(); // added in libsodium 1.0.15
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
    
    public static NativeLong cryptoPwHashScryptSalsa208Sha256SaltBytes()
    {
        return sodium().crypto_pwhash_scryptsalsa208sha256_saltbytes();
    }

   /**
    * Encrypts a message with recipient's public key.
    * 
    * Usage: Alice encrypts a message with Bob's public key and creates authentication tag with her private key
    * 
    * @param message The message to encrypt
    * @param nonce {@link SodiumLibrary#cryptoBoxNonceBytes()} bytes of nonce. It must be preserved  because it will be needed during decryption
    * @param publicKey Recipient's public key for encrypting the message
    * @param privateKey Sender's private key for creating authentication tag
    * @throws SodiumLibraryException on error
    * @return encrypted message as an array of bytes
    */    
    public static byte[] cryptoBoxEasy(byte[] message, byte[] nonce,
            byte[] publicKey, byte[] privateKey) throws SodiumLibraryException
    {
        NativeLong nonce_len = sodium().crypto_box_noncebytes();
        if (nonce.length != nonce_len.intValue())
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + "bytes, it must be" + nonce_len + " bytes");
        }
        byte[] cipherText = new byte[(sodium().crypto_box_macbytes().intValue() + message.length)];
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
    
   /**
    * Recipient decrypts a message with his private key.
    * 
    * Usage: Bob (recipient) verifies the message with Alice's (sender) public key and 
    * decrypts the message with his private key.
    *
    * @param cipherText Message to decrypt
    * @param nonce Nonce used during encryption 
    * @param publicKey Sender's (Alice) public key for verifying the message
    * @param privateKey Recipient's (Bob)  Private key to decrypt the message
    * @throws SodiumLibraryException on error
    * @return Decrypted message as an array of bytes.
    */
    public static byte[] cryptoBoxOpenEasy(byte[] cipherText, byte[]nonce, 
            byte[] publicKey, byte[] privateKey) throws SodiumLibraryException
    {
        NativeLong nonce_len = sodium().crypto_box_noncebytes();
        if (nonce.length != nonce_len.intValue())
        {
            throw new SodiumLibraryException("nonce is " + nonce.length + "bytes, it must be" + nonce_len + " bytes");
        }
        byte[] decrypted = new byte[(int) (cipherText.length - sodium().crypto_box_macbytes().intValue())];
        int rc = sodium().crypto_box_open_easy(decrypted, cipherText, 
                cipherText.length, nonce, 
                publicKey, privateKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_open_easy() failed, returned " + rc + ", expected 0");
        }
        
        return decrypted;
    }
    
    /**
     * Encrypts a message with recipient's public key.
     * 
     * Usage: Alice can anonymously send a message to Bob by encrypting the message with his public key.
     * 
     * @param message The message bytes to encrypt
     * @param recipientPublicKey Recipient's public key 
     * @throws SodiumLibraryException on error
     * @return Encrypted message bytes. The length of the cipher text will be 
     * {@link SodiumLibrary#cryptoBoxSealBytes()} + message.length
     * @see <a href="https://download.libsodium.org/libsodium/content/public-key_cryptography/sealed_boxes.html" target="_blank">Sealed boxes</a>
     */
    public static byte[] cryptoBoxSeal(byte[] message, byte[] recipientPublicKey) throws SodiumLibraryException
    {
        if (logger.isDebugEnabled()) {
            logger.debug("message len: " + message.length);
        }

        byte[] cipherText = new byte[(sodium().crypto_box_sealbytes().intValue() + message.length)];
        int rc = sodium().crypto_box_seal(cipherText, message, message.length, recipientPublicKey);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_seal() failed, returned " + rc + ", expected 0");
        }
        return cipherText;
    }
    
   /**
    * Decrypts a ciphertext using recipient's  key pair.
    * 
    * Only the recipient can decrypt the message with his private key but the recipient can not identify the sender.
    * 
    * @param cipherText Ciphertext to decrypt
    * @param pk Recipient's public key
    * @param sk Recipient's private Key
    * @throws SodiumLibraryException on error
    * @return Decrypted plaintext bytes. 
    * @throws SodiumLibraryException on error
    * @see <a href="https://download.libsodium.org/libsodium/content/public-key_cryptography/sealed_boxes.html" target="_blank">Sealed boxes</a>
    */
    public static byte[] cryptoBoxSealOpen(byte[] cipherText,byte[] pk, byte[] sk) throws SodiumLibraryException
    {
        byte[] decrypted = new byte[(int) (cipherText.length - sodium().crypto_box_sealbytes().intValue())];
        int rc = sodium().crypto_box_seal_open(decrypted, cipherText, cipherText.length, pk, sk);
        if (rc != 0)
        {
            throw new SodiumLibraryException("libsodium crypto_box_seal_open() failed, returned " + rc + ", expected 0");
        }
        return decrypted;
        
    }
    ////////////////////
}
