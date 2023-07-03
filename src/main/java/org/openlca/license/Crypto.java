package org.openlca.license;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * <p>
 * The {@link Crypto} class is used to encrypt and decrypt InputStream.
 * The encryption is symmetric and the algorithm used is the AES/ECB.
 * </p>
 * <p>
 * This class is only composed of static methods and can simply be used as
 * follow:
 * <p><code>
 * Crypto.[encrypt/decrypt](password, salt, input, output);
 * </code></p>
 */
public class Crypto {

	public static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

	private static final String ALGORITHM = "AES";
	private static final String HASH = "PBKDF2WithHmacSHA1";
	private static final int ITERATION = 65_536;
	private static final int KEY_LENGTH = 128;
	public static final int BUFFER_SIZE = 8_192;

	public static void encrypt(char[] password, byte[] salt, InputStream in,
			OutputStream out) throws IOException, BadPaddingException {
		var cipher = getCipher(Cipher.ENCRYPT_MODE, password, salt);
		doCrypto(cipher, in, out);
	}

	public static void decrypt(char[] password, byte[] salt, InputStream in,
			OutputStream out) throws IOException, BadPaddingException {
		var cipher = getCipher(Cipher.DECRYPT_MODE, password, salt);
		doCrypto(cipher, in, out);
	}

	public static SecretKeySpec getKeyFromPassword(char[] pass, byte[] salt) {
		var secret = getSecret(pass, salt);
		return getKeyFromSecret(secret);
	}

	public static byte[] getSecret(char[] pass, byte[] salt) {
		var spec = new PBEKeySpec(pass, salt, ITERATION, KEY_LENGTH);
		try {
			var factory = SecretKeyFactory.getInstance(HASH);
			return factory.generateSecret(spec).getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException("Error while getting the secret key from the "
					+ "password and salt.", e);
		}
	}

	public static SecretKeySpec getKeyFromSecret(byte[] secret) {
		return new SecretKeySpec(secret, ALGORITHM);
	}

	/**
	 * Encrypt or decrypt a stream into another stream.
	 *
	 * @param cipher encryption or decryption cipher.
	 * @param in     stream to decrypt or encrypt from.
	 * @param out    stream to decrypt or encrypt to.
	 */
	static void doCrypto(Cipher cipher, InputStream in, OutputStream out)
			throws IOException, BadPaddingException {
		var buffer = new byte[BUFFER_SIZE];
		int len;
		while ((len = in.read(buffer)) != -1) {
			var result = cipher.update(buffer, 0, len);
			if (result != null) {
				out.write(result);
			}
		}

		try {
			var result = cipher.doFinal();
			if (result != null) {
				out.write(result);
			}
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		}
	}

	private static Cipher getCipher(int mode, SecretKeySpec key) {
		try {
			var cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(mode, key);
			return cipher;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
						 InvalidKeyException e) {
			var verbose = mode == Cipher.DECRYPT_MODE ? "decrypting" : "encrypting";
			throw new RuntimeException("Error while creating the " + verbose
					+ " cipher.", e);
		}
	}

	public static Cipher getCipher(int mode, char[] password, byte[] salt) {
		var key = getKeyFromPassword(password, salt);
		return getCipher(mode, key);
	}

	public static Cipher getCipher(int mode, byte[] secret) {
		var key = getKeyFromSecret(secret);
		return getCipher(mode, key);
	}

}
