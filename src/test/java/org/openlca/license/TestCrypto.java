package org.openlca.license;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.crypto.BadPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;


public class TestCrypto {

	public File inputFile;

	/* This folder and the files created in it will be deleted after
	 * tests are run, even in the event of failures or exceptions.
	 */
	@Rule
	public TemporaryFolder folder = new TemporaryFolder();

	/* executed before every test: create temporary files */
	@Before
	public void setUp() {
		try {
			inputFile = folder.newFile("test.bin");
			try (var outputStream = new FileOutputStream(inputFile)) {
				outputStream.write("test123".getBytes());
			}
		}
		catch(IOException e) {
			System.err.println("Error while creating the temporary test file in " +
							this.getClass().getSimpleName());
		}
	}

	@Test
	public void testTransitivity() throws IOException, BadPaddingException {
		var password = "password123";
		var salt = generateSalt();

		var encryptedFile = folder.newFile("test.encrypted");
		var decryptedFile = folder.newFile("test.decrypted");

		try (var in = new FileInputStream(inputFile);
				 var out = new FileOutputStream(encryptedFile)) {
			Crypto.encrypt(password.toCharArray(), salt, in, out);
		}

		try (var in = new FileInputStream(encryptedFile);
				 var out = new FileOutputStream(decryptedFile)) {
			Crypto.decrypt(password.toCharArray(), salt, in, out);
		}

		assertArrayEquals(Files.readAllBytes(inputFile.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	public static byte[] generateSalt() {
		var random = new SecureRandom();
		var salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

}
