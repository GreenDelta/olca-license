package org.openlca.license.signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.Licensor;
import org.openlca.license.TestUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.Security;
import java.util.Map;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class TestSignature {

	private File folder;
	private KeyPair keyPair;
	private File file1;
	private File zip;
	private SignatureVerifier verifier;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();


	@Before
	public void createTestFolder() throws IOException {
		folder = tempFolder.newFolder("folder");
		/*folder = new File("folder");
		folder.delete();
		folder.mkdir();*/
		file1 = new File(folder, "file1");
		Files.write(file1.toPath(), "one".getBytes());
		var file2 = new File(folder, "file2");
		Files.write(file2.toPath(), "two".getBytes());
		zip = tempFolder.newFile("folder.zip");
		/*zip = new File("folder.zip");
		zip.delete();*/
		TestUtils.zip(folder, zip);

		keyPair = Licensor.generateKeyPair();
		verifier = new SignatureVerifier(keyPair.getPublic(), signFolder());
	}

	@Test
	public void testValidSign() throws IOException {
		assertTrue(verifier.verify(folder));
	}

	@Test
	public void testInvalidSignAddingFile() throws IOException {
		var file3 = new File(folder, "file3");
		Files.write(file3.toPath(), "three".getBytes());

		assertFalse(verifier.verify(folder));
	}

	@Test
	public void testInvalidSignRemovingFile() throws IOException {
		assert file1.delete();
		assertFalse(verifier.verify(folder));
	}

	@Test
	public void testInvalidSignEditingFile() throws IOException {
		Files.write(file1.toPath(), "three".getBytes());
		assertFalse(verifier.verify(folder));
	}

	private Map<String, byte[]> signFolder() throws IOException {
		var signer = new Signer(keyPair.getPrivate());

		var signZip = tempFolder.newFile("sign.zip");
		try (var input = new ZipInputStream(new FileInputStream(zip));
				 var output = new ZipOutputStream(new FileOutputStream(signZip))) {
			var zipEntry = input.getNextEntry();
			while (zipEntry != null) {
				output.putNextEntry(zipEntry);
				signer.sign(input, zipEntry.getName(), output);
				zipEntry = input.getNextEntry();
			}
		}
		return signer.getSignatures();
	}

}
