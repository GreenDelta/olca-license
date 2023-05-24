package org.openlca;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

import org.junit.rules.TemporaryFolder;
import org.openlca.license.Crypto;
import org.openlca.license.CryptoException;


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
				outputStream.write("test".getBytes());
			}
		}
		catch(IOException e) {
			System.err.println("Error while creating the temporary test file in " +
							this.getClass().getSimpleName());
		}
	}

	@Test
	public void testTransitivity() {
		var password = "password";
		var salt = Crypto.generateSalt();

		try {
			var encryptedFile = folder.newFile("test.encrypted");
			var decryptedFile = folder.newFile("test.decrypted");

			Crypto.encrypt(password, salt, inputFile, encryptedFile);
			Crypto.decrypt(password, salt, encryptedFile, decryptedFile);
			assert Arrays.equals(
					Files.readAllBytes(inputFile.toPath()),
					Files.readAllBytes(decryptedFile.toPath()));
		} catch (CryptoException | IOException e) {
			throw new RuntimeException(e);
		}
	}

}
