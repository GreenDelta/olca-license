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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Crypto {

	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
	private static final String HASH = "PBKDF2WithHmacSHA1";

	public static void encrypt(String password, byte[] salt, InputStream in,
			OutputStream out) throws IOException {
		var key = getKeyFromPassword(password, salt);
		try {
			var cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			doCrypto(cipher, in, out);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
						 InvalidKeyException e) {
			throw new RuntimeException("Error while encrypting.", e);
		}
	}

	public static void decrypt(String password, byte[] salt, InputStream in,
			OutputStream out) throws IOException {
		var key = getKeyFromPassword(password, salt);
		try {
			var cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(Cipher.DECRYPT_MODE, key);
			doCrypto(cipher, in, out);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
						 InvalidKeyException e) {
			throw new RuntimeException("Error while decrypting.", e);
		}
	}

	private static SecretKeySpec getKeyFromPassword(String pass, byte[] salt) {
		var spec = new PBEKeySpec(pass.toCharArray(), salt, 65536, 128);
		try {
			var factory = SecretKeyFactory.getInstance(HASH);
			var encoded = factory.generateSecret(spec).getEncoded();
			return new SecretKeySpec(encoded, ALGORITHM);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException("Error while getting the secret key from the "
					+ "password and salt.", e);
		}
	}

	public static byte[] generateSalt() {
		var random = new SecureRandom();
		var salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

	private static void doCrypto(Cipher cipher, InputStream in, OutputStream out)
			throws IOException {
		var buffer = new byte[1024];
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
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

}

