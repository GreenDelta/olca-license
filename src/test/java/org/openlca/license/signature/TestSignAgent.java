package org.openlca.license.signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.SignAgent;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;


public class TestSignAgent {

	private File folder;
	private byte[] signature;
	private KeyPair keyPair;
	private File file1;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void createAndSign() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		folder = tempFolder.newFolder("folder");
		file1 = new File(folder, "file1");
		Files.write(file1.toPath(), "one".getBytes());
		var file2 = new File(folder, "file2");
		Files.write(file2.toPath(), "two".getBytes());
		var keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048);
		keyPair = keyPairGenerator.generateKeyPair();

		signature = SignAgent.signFolder(folder, keyPair.getPrivate());
	}

	@Test
	public void testValidSign() throws IOException {
		assert SignAgent.verifySignature(folder, signature, keyPair.getPublic());
	}

	@Test
	public void testInvalidSignAddingFile() throws IOException {
		var file3 = new File(folder, "file3");
		Files.write(file3.toPath(), "three".getBytes());

		assert !SignAgent.verifySignature(folder, signature, keyPair.getPublic());
	}

	@Test
	public void testInvalidSignRemovingFile() throws IOException {
		assert file1.delete();
		assert !SignAgent.verifySignature(folder, signature, keyPair.getPublic());
	}

	@Test
	public void testInvalidSignEditingFile() throws IOException {
		Files.write(file1.toPath(), "three".getBytes());
		assert !SignAgent.verifySignature(folder, signature, keyPair.getPublic());
	}

}
