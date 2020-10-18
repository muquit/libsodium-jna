package test.com.muquit.libsodiumjna;

import static com.muquit.libsodiumjna.SodiumLibrary.sodium;
import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import com.muquit.libsodiumjna.SodiumCrypto;
import com.muquit.libsodiumjna.SodiumKeyPair;
import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.SodiumSecretBox;
import com.muquit.libsodiumjna.SodiumUtils;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import com.sun.jna.Platform;

public class TestSodiumLibrary
{
	private final static Logger logger = LoggerFactory.getLogger(TestSodiumLibrary.class);
	private static String libraryPath = null;
	
	@Rule
    public ExpectedException thrown = ExpectedException.none();

	@Before
	public void initSodium()
	{
		String platform = System.getProperty("os.name");
		logger.info("Platform: " + platform);
		if (Platform.isMac())
		{
			libraryPath = "/usr/local/lib/libsodium.dylib";
			logger.info("Library path in Mac: " + libraryPath);
		}
		else if (Platform.isWindows())
		{
			//libraryPath = "C:/libsodium/libsodium.dll";
			libraryPath = "d:/muquit/libsodium-1.0.15/x64/Release/v141/dynamic/libsodium.dll";
			logger.info("Library path in Windows: " + libraryPath);
		}
		else
		{
			libraryPath = "/usr/local/lib/libsodium.so";
			logger.info("Library path in "  + "platform: " + platform + " " + libraryPath);
			
		}
		logger.info("Initialize libsodium...");
		SodiumLibrary.setLibraryPath(libraryPath);
		logger.info("sodium object: " + Integer.toHexString(System.identityHashCode(sodium())));
		logger.info("Library path: " + libraryPath);
		String v = sodium().sodium_version_string();
		logger.info("libsodium version: " + v);
	}
	
	/* convert binary to hex */
	public String binary2Hex(byte[] data)
	{
		return SodiumUtils.binary2Hex(data);
	}
	
	public byte[] hex2Binary(String hex)
	{
		return SodiumUtils.hex2Binary(hex);
	}
	
	@Test
	public void testLibSodiumVersion()
	{
		String version = SodiumLibrary.libsodiumVersionString();
		assertEquals("1.0.18", version);
	}

	@Test
	public void testRandomBytes()
	{
		int n = SodiumLibrary.cryptoNumberSaltBytes();
		logger.info("Generate " + n + " random bytes");
		byte[] salt = SodiumLibrary.randomBytes(n);
		logger.info("Generated " + salt.length + " random bytes");
	    String hex = SodiumUtils.binary2Hex(salt);
	    logger.info("Random bytes; " + hex);
	    assertEquals(n * 2, hex.length());
	}
	
	@Test
	public void testDeriveKeyArgon2() throws SodiumLibraryException
	{
		String hexString = TestVectors.PWHASH_ARGON2_SALT;
		byte[] saltBytes = SodiumUtils.hex2Binary(hexString);
		byte[] passPhraseBytes = TestVectors.PASSWORD;
		byte[] key;
		String keyHex = null;
		try
		{
			key = SodiumLibrary.cryptoPwhashArgon2i(passPhraseBytes, saltBytes);
			keyHex = SodiumUtils.binary2Hex(key);
			logger.info("key: " + keyHex);
			assertEquals(keyHex,TestVectors.PWHASH_ARGON2_KEY);
		} catch (SodiumLibraryException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw(e);
		}
        
        key = SodiumLibrary.cryptoPwhashArgon2i(passPhraseBytes, saltBytes);
		keyHex = SodiumUtils.binary2Hex(key);
        assertEquals(keyHex,TestVectors.PWHASH_ARGON2_KEY);
	}
	@Test
	public void testDeriveKeyVerify() throws SodiumLibraryException
	{
		String password = new String("বাংলা");
		// convert to UTF-8 encoded bytes
		byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8); // requires jdk 1.7+
		String key = SodiumLibrary.cryptoPwhashStr(passwordBytes);
		boolean rc = SodiumLibrary.cryptoPwhashStrVerify(key, passwordBytes);
		assertEquals(true,rc);
	}
	
	/*
	@Test
	public void testPasswordStorageArgon2()
	{
		byte[] hashedPassword = SodiumLibrary.cryptoPwhashStr(TestVectors.PASSWORD);
		String hashedPasswordStr = Native.toString(hashedPassword);
		logger.info("hashed password: " + hashedPassword);
		logger.info("hashed password string: " + hashedPasswordStr);
		
		boolean rc = SodiumLibrary.cryptoPwhashStrVerify(hashedPassword, TestVectors.PASSWORD);
		assertEquals(true,rc);
		
		// test converting String to byes and convert back to String
		byte[] p = hashedPasswordStr.getBytes();
		String b = Native.toString(p);
		logger.info("back: " + b);
		assertEquals(b,hashedPasswordStr);
	}
	*/
	
	@Test
	public void testDeriveKeyScrypt() throws SodiumLibraryException
	{
		String hexString = TestVectors.PWHASH_SCRYPT_SALT;
		byte[] saltBytes = SodiumUtils.hex2Binary(hexString);
		byte[] passPhraseBytes = TestVectors.PASSWORD;
		byte[] key = SodiumLibrary.cryptoPwhashScrypt(passPhraseBytes, saltBytes);
		String keyHex = SodiumUtils.binary2Hex(key);
		logger.info("key: " + keyHex);
        assertEquals(keyHex,TestVectors.PWHASH_SCRYPT_KEY);
	}
	
	@Test
	public void testKeyPair() throws SodiumLibraryException
	{
	    SodiumKeyPair kp = SodiumLibrary.cryptoBoxKeyPair();
	    String hex = SodiumUtils.binary2Hex(kp.getPublicKey());
	    logger.info("Public key: " + hex);
	    hex = SodiumUtils.binary2Hex(kp.getPrivateKey());
	    logger.info("Private key: " + hex);
	}
	
	@Test
	public void testPublicKeyFromPrivateKey() throws SodiumLibraryException
	{
	    SodiumKeyPair kp = SodiumLibrary.cryptoBoxKeyPair();
	    String hex = SodiumUtils.binary2Hex(kp.getPublicKey());
	    logger.info("public key: " + hex);
	    byte[] publicKey = SodiumLibrary.cryptoPublicKey(kp.getPrivateKey());
	    String hexPublicKey = SodiumUtils.binary2Hex(publicKey);
	    logger.info("calculated: " + hexPublicKey);
	    assertEquals(hex,hexPublicKey);
	}
	
	@Test
	public void testCryptoSecretBoxEasy() throws SodiumLibraryException
	{
	    byte[] key = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_KEY);
	    byte[] nonce = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_NONCE);
	    byte[] message = TestVectors.MESSAGE;
	    byte[] cipherText = SodiumLibrary.cryptoSecretBoxEasy(message,nonce,key);
	    String cipherTextHex = SodiumUtils.binary2Hex(cipherText);
        assertEquals(cipherTextHex,TestVectors.SECRET_BOX_CIPTHER_TEXT);
	}
	
	@Test 
	public void testCryptoSecretBoxEasyEcryptDecrypt() throws SodiumLibraryException
	{
		int nonceBytesLength = SodiumLibrary.cryptoSecretBoxNonceBytes().intValue();
		byte[] nonceBytes = SodiumLibrary.randomBytes((int) nonceBytesLength);
		String message = "This is a message";
		byte[] messageBytes = message.getBytes();
		byte[] key = SodiumLibrary.randomBytes((int) SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());
		byte[] cipherText = SodiumLibrary.cryptoSecretBoxEasy(messageBytes, nonceBytes, key);
		
		// now decrypt
		byte[] decryptedMessageBytes = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText, nonceBytes, key);
		String decryptedMessage;
		try
		{
			decryptedMessage = new String(decryptedMessageBytes, "UTF-8");
			assertEquals(message, decryptedMessage);
		} catch (UnsupportedEncodingException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testCryptoSecretBoxOpenEasy() throws SodiumLibraryException
	{
	    byte[] key = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_KEY);
	    byte[] nonce = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_NONCE);
	    byte[] cipherText = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_CIPTHER_TEXT);
	    byte[] message = SodiumLibrary.cryptoSecretBoxOpenEasy(cipherText,nonce,key);
	    String messageHex = SodiumUtils.binary2Hex(message);
        assertEquals(messageHex,SodiumUtils.binary2Hex(TestVectors.MESSAGE));
	}
	
	@Test
	public void testCryptoSecretBoxDetached() throws SodiumLibraryException
	{
	    byte[] key = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_KEY);
	    byte[] nonce = SodiumUtils.hex2Binary(TestVectors.SECRET_BOX_NONCE);
	    byte[] message = TestVectors.MESSAGE;
	    SodiumSecretBox secretBox = SodiumLibrary.cryptoSecretBoxDetached(message,nonce,key);
	    String cipherTextHex = SodiumUtils.binary2Hex(secretBox.getCipherText());
	    String macHex = SodiumUtils.binary2Hex(secretBox.getMac());
	    assertEquals(TestVectors.SECRET_BOX_DETACHED_CIPHER_TEXT, cipherTextHex);
	    assertEquals(TestVectors.SECRET_BOX_DETACHED_MAC, macHex);
	}
	
	// Test issue #1
	@Test
	public void testCryptoSecretBoxDetached2() throws SodiumLibraryException
	{
	    String messageStr = "This is a message";
	    byte[] message = messageStr.getBytes();
	    // generate key
	    byte[] key = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxKeyBytes().intValue());
	    // generate nonce
	    byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxNonceBytes().intValue());
	    
	    // encrypt
	    SodiumSecretBox secretBox = SodiumLibrary.cryptoSecretBoxDetached(message,nonce,key);
	    
	    // decrypt
	    byte[] decryptedBytes = SodiumLibrary.cryptoSecretBoxOpenDetached(secretBox, nonce, key);
        try
        {
            String decryptedMessage = new String(decryptedBytes, "UTF-8");
            logger.info("Decrypted message: " + decryptedMessage);
            assertEquals(messageStr, decryptedMessage);
        } catch (UnsupportedEncodingException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
	    
	}
	
	@Test
	public void testCryptoBoxEasy() throws SodiumLibraryException
	{
		/* alice encrypts with bob's public key  and bob decrypts with his private key */
		SodiumKeyPair aliceKeyPair = SodiumLibrary.cryptoBoxKeyPair();
		SodiumKeyPair bobKeyPair = SodiumLibrary.cryptoBoxKeyPair();
		byte[] bobPublicKey = SodiumUtils.hex2Binary(TestVectors.CRYPTO_BOX_BOB_PUBLIC_KEY);
		byte[] bobPrivateKey = SodiumUtils.hex2Binary(TestVectors.CRYPTO_BOX_BOB_PRIVATE_KEY);

		byte[] alicePublicKey = SodiumUtils.hex2Binary(TestVectors.CRYPTO_BOX_ALICE_PUBLIC_KEY);
		byte[] alicePrivateKey = SodiumUtils.hex2Binary(TestVectors.CRYPTO_BOX_ALICE_PRIVATE_KEY);

		byte[] nonce = SodiumUtils.hex2Binary(TestVectors.CRYPTO_BOX_NONCE);
		// Alice Encrypts with bob's public key
		byte[] cipherText = SodiumLibrary.cryptoBoxEasy(
				TestVectors.MESSAGE, nonce, 
				bobPublicKey,
				alicePrivateKey);
		String cipherHex = SodiumUtils.binary2Hex(cipherText);
		logger.info("Ciphertext: " + cipherHex);
        assertEquals(cipherHex,TestVectors.CRYPTO_BOX_ALICE_CIPHERTEXT);
        
        // Bob Decrypts with his Private key
        byte[] decrypted = SodiumLibrary.cryptoBoxOpenEasy(
        		cipherText, nonce,
        		alicePublicKey, bobPrivateKey);
        String decryptedHex = SodiumUtils.binary2Hex(decrypted);
        logger.info("decrypted: " + decryptedHex);
        assertEquals(TestVectors.CRYPTO_BOX_BOB_PLAINTEXT,decryptedHex);
	}
	
	@Test
	public void testCryptoBoxEasy2() throws SodiumLibraryException
	{
	    // Alice generates key pair
		SodiumKeyPair aliceKeyPair = SodiumLibrary.cryptoBoxKeyPair();
		byte[] alicePublicKey = aliceKeyPair.getPublicKey();
		byte[] alicePrivateKey = aliceKeyPair.getPrivateKey();
   
		// Bob generates key pair
		SodiumKeyPair bobKeyPair = SodiumLibrary.cryptoBoxKeyPair();
 		byte[] bobPublicKey = bobKeyPair.getPublicKey();
		byte[] bobPrivateKey = bobKeyPair.getPrivateKey();
		
		// Generate nonce
		byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoBoxNonceBytes().intValue());

		String secretMessage = "Hi Bob, This is Alice";
		// Alice encrypts the message with Bob's public key
		byte[] cipherText = SodiumLibrary.cryptoBoxEasy(
	        secretMessage.getBytes(), nonce, 
			bobPublicKey,
			alicePrivateKey);
		String cipherHex = SodiumUtils.binary2Hex(cipherText);
		logger.info("Ciphertext: " + cipherHex);

        // Bob Decrypts ciphertext with his Private key
        byte[] decrypted = SodiumLibrary.cryptoBoxOpenEasy(
        		cipherText, nonce,
        		alicePublicKey,
        		bobPrivateKey);
        String decrypteString;
        try
        {
            decrypteString = new String(decrypted, "UTF-8");
            logger.info("decrypted: " + decrypteString);
        } catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
        }
	}

	@Test
	public void testCryptoBoxSeal2() throws SodiumLibraryException
	{
		// Bob generates key pair
		SodiumKeyPair bobKeyPair = SodiumLibrary.cryptoBoxKeyPair();
 		byte[] bobPublicKey = bobKeyPair.getPublicKey();
		byte[] bobPrivateKey = bobKeyPair.getPrivateKey();
   
		String secretMessage = "Hi Bob, This is Alice";
		// Alice encrypts with Bob's public key
		byte[] cipherText = SodiumLibrary.cryptoBoxSeal(secretMessage.getBytes(), bobPublicKey);
		String cipherHex = SodiumUtils.binary2Hex(cipherText);
		logger.info("Ciphertext: " + cipherHex);
		logger.info("Ciphertext length : " + cipherText.length);
		
		long ciperTextlength = SodiumLibrary.cryptoBoxSealBytes().intValue() + secretMessage.length();
		logger.info("length: " + ciperTextlength);

		
		// Bob decrypts with his private key
		byte[] decrypted = SodiumLibrary.cryptoBoxSealOpen(cipherText, bobPublicKey, bobPrivateKey);

        try
        {
            String decrypteString = new String(decrypted, "UTF-8");
            logger.info("decrypted: " + decrypteString);
        } catch (UnsupportedEncodingException e)
        {
            e.printStackTrace();
        }
	}

	@Test
	public void testCrytoBoxSeal() throws SodiumLibraryException
	{
		byte[] recipientPublicKey = SodiumUtils.hex2Binary(TestVectors.SEALBOX_RECIPIENT_PUBLIC_KEY);
		byte[] recipientPrivateKey = SodiumUtils.hex2Binary(TestVectors.SEALBOX_RECIPIENT_PRIVATE_KEY);
	    byte[] message = TestVectors.MESSAGE;
	    String messageHex = SodiumUtils.binary2Hex(message);
	    logger.info("message: " + messageHex);
	    logger.info("public key: " + TestVectors.SEALBOX_RECIPIENT_PUBLIC_KEY);
	    byte[] cipherText = SodiumLibrary.cryptoBoxSeal(message, recipientPublicKey);
	    String hex = SodiumUtils.binary2Hex(cipherText);
	    logger.info("ciphertext: " + hex);
	    logger.info("ct len: " + cipherText.length);

	    assertNotEquals(TestVectors.SEALBOX_CIPHERTEXT, hex);

	    byte[] decrypted = SodiumLibrary.cryptoBoxSealOpen(cipherText, recipientPublicKey, recipientPrivateKey);
	    hex = SodiumUtils.binary2Hex(decrypted);
	    logger.info("decrypted: " + hex);
        assertEquals(messageHex,hex);
	}
	
	
	/**
	 * Test encrypt with own public key and decrypt with own private key
	 * @throws SodiumLibraryException
	 * <p>
	 * @author muquit@muquit.com - Mar 9, 2017
	 */
	@Test
	public void testEncryptDecryptOwnKeyPair() throws SodiumLibraryException
	{
	    SodiumKeyPair aliceKp = SodiumLibrary.cryptoBoxKeyPair();
	    
	    String secret = "this is a secret";
	    byte[] cipherText = SodiumLibrary.cryptoBoxSeal(secret.getBytes(), aliceKp.getPublicKey());
	    logger.info("ciphertext length: " + cipherText.length);
	    
	    byte[] plainTextBytes = SodiumLibrary.cryptoBoxSealOpen(cipherText, aliceKp.getPublicKey(), aliceKp.getPrivateKey());
	    try
        {
            String decryptedMessage = new String(plainTextBytes, "UTF-8");
            assertEquals(secret, decryptedMessage);
        } catch (UnsupportedEncodingException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
	}
	
	private byte[] makeSalt()
	{
		return SodiumLibrary.randomBytes(SodiumLibrary.cryptoPwhashSaltBytes());
	}
	
	private byte[] makeNonce()
	{
	    return SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxNonceBytes().intValue());
	}
	
	private byte[] generateKey(String password,byte[] salt) throws SodiumLibraryException
	{
		byte[] key = SodiumLibrary.cryptoPwhashArgon2i(password.getBytes(), salt);
		return key;
	}
	
	@Test
	public void testCryptoAuth() throws SodiumLibraryException
	{
		byte[] key = SodiumUtils.hex2Binary(TestVectors.SECRET_KEY_AUTH_KEY);
		byte[] mac = SodiumLibrary.cryptoAuth(TestVectors.MESSAGE, key);
		String hex = SodiumUtils.binary2Hex(mac);
		assertEquals(TestVectors.SECRET_KEY_AUTH_MAC,hex);
		
		boolean authenticated = SodiumLibrary.cryptoAuthVerify(mac, TestVectors.MESSAGE, key);
		assertEquals(true,authenticated);
	}
	
	@Test
	public void testPasswordHash() throws SodiumLibraryException
	{
		TestInitializeLibrary ti = new TestInitializeLibrary();
		String passwords[] = 
		{
			"test1",
			"test2",
			"test3",
			"test4",
			"test5",
			"test6",
			"test7"
		};
		for (String password:passwords)
		{
			String hashedPassword = ti.hashPassword(password);
			System.out.println(password + "->" + hashedPassword);
			boolean rc = ti.check(password, hashedPassword);
			assertEquals(true, rc);
		}
	}

	@Test
	public void testEncryptPrivateKey() throws SodiumLibraryException
	{
		String passPhrase = "This is a passphrase";
		byte[] salt = SodiumLibrary.randomBytes(SodiumLibrary.cryptoPwhashSaltBytes());
		String hex = SodiumUtils.binary2Hex(salt);

		// create salt for derive key from pass phrase
		logger.info("Generated " + salt.length + " bytes of salt");
		logger.info(hex);
		logger.info("Derive key from passphrase");
		byte[] key = SodiumLibrary.cryptoPwhashArgon2i(passPhrase.getBytes(), salt);
		logger.info("Dervived " + key.length + " bytes long key");
		hex = SodiumUtils.binary2Hex(key);
		logger.info(hex);
		
		// generate key pair
		logger.info("Generate key pair");
		SodiumKeyPair kp  = SodiumLibrary.cryptoBoxKeyPair();
		byte[] publicKey  = kp.getPublicKey();
		byte[] privateKey = kp.getPrivateKey();
		String hexPublicKey  = SodiumUtils.binary2Hex(publicKey);
		String hexPrivateKey = SodiumUtils.binary2Hex(privateKey);
		logger.info("Generated Public key " + publicKey.length + " bytes");
		logger.info(hexPublicKey);
		logger.info("Generated Private key " + privateKey.length + " bytes");
		logger.info(hexPrivateKey);
		
		// create nonce for encrypting private key
		byte[] nonce = SodiumLibrary.randomBytes(SodiumLibrary.cryptoSecretBoxNonceBytes().intValue());
		hex = SodiumUtils.binary2Hex(salt);
		logger.info("Generated " + nonce.length + " bytes of nonce");
		logger.info(hex);
		
		// encrypt the private key with nonce and key
		byte[] encryptedPrivateKey = SodiumLibrary.cryptoSecretBoxEasy(privateKey, nonce, key);
		// decrypt the private key again
		byte[] decryptedPrivateKey = SodiumLibrary.cryptoSecretBoxOpenEasy(encryptedPrivateKey, nonce, key);
		logger.info("Decrypted private key: " + SodiumUtils.binary2Hex(decryptedPrivateKey));

		// use a wrong key, we expect decryption to fail
		String wrongPassPhrase = "This is a wrong passphrase";
		key = SodiumLibrary.cryptoPwhashArgon2i(wrongPassPhrase.getBytes(), salt);
		thrown.expect(SodiumLibraryException.class);
		SodiumLibrary.cryptoSecretBoxOpenEasy(encryptedPrivateKey, nonce, key);
	}
	
	@Test
	public void testGenPublicKeyFromPrivateKey() throws SodiumLibraryException
	{
	    SodiumKeyPair kp = SodiumLibrary.cryptoBoxKeyPair();
	    String publicKeyHex = SodiumUtils.binary2Hex(kp.getPublicKey());
	    String privateKeyHex = SodiumUtils.binary2Hex(kp.getPrivateKey());
	    logger.info("Public key: " + publicKeyHex);
	    logger.info("Private key: " + privateKeyHex);
	    byte[] publicKeyGenerated = SodiumLibrary.cryptoPublicKey(kp.getPrivateKey());
	    String publicKeyGeneratedHex = SodiumUtils.binary2Hex(publicKeyGenerated);
	    logger.info("Public key from private key: "+  publicKeyGeneratedHex);
	    assertArrayEquals(publicKeyGenerated, kp.getPublicKey());
	}	
	

	@After
	public void doneTesting()
	{
		logger.info("Done Testing Crypto");
	}
	

}
