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
			try (FileOutputStream outputStream = new FileOutputStream(inputFile)) {
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
		String password = "password123";
		byte[] salt = generateSalt();

		File encryptedFile = folder.newFile("test.encrypted");
		File decryptedFile = folder.newFile("test.decrypted");

		try (FileInputStream in = new FileInputStream(inputFile);
				 FileOutputStream out = new FileOutputStream(encryptedFile)) {
			Crypto.encrypt(password.toCharArray(), salt, in, out);
		}

		try (FileInputStream in = new FileInputStream(encryptedFile);
				 FileOutputStream out = new FileOutputStream(decryptedFile)) {
			Crypto.decrypt(password.toCharArray(), salt, in, out);
		}

		assertArrayEquals(Files.readAllBytes(inputFile.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	public static byte[] generateSalt() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

}
