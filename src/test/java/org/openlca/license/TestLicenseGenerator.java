package org.openlca.license;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.certificate.CertUtils;
import org.openlca.license.certificate.LicenseInfo;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.Date;
import java.util.Objects;

import static org.junit.Assert.*;
import static org.openlca.license.LicenseGenerator.JSON;
import static org.openlca.license.TestUtils.getTestLicenseInfo;


public class TestLicenseGenerator {

	private File ca;
	private static final String PASSWORD_LIB = "passlib123";
	private static final String PASSWORD_CA = "passca123";

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void initializeCertificateAuthority() throws IOException,
			URISyntaxException {
		var caURL = getClass().getResource("nexus-ca");

		ca = new File(Objects.requireNonNull(caURL).toURI());

		// Add password file
		var pass = new File(ca, ca.getName() + ".pass");
		var fileWriter = new FileWriter(pass);
		fileWriter.write(PASSWORD_CA);
		fileWriter.close();
	}

	@Test
	public void testCreateLicenseGeneratorInstance()
			throws IOException {
		var generator = LicenseGenerator.getInstance(ca);

		assertNotNull(generator);
		assertNotNull(generator.certAuthority);
		assertNotNull(generator.publicKeyCA);
		assertNotNull(generator.privateKeyCA);
		assertTrue(generator.certAuthority.isValidOn(new Date()));
		assertEquals("RSA", generator.publicKeyCA.getAlgorithm());
		assertEquals("RSA", generator.privateKeyCA.getAlgorithm());
	}

	@Test
	public void testCreateLicensedLibrary() throws Exception {
		var generator = LicenseGenerator.getInstance(ca);
		var library = createTestLibrary();
		var info = getTestLicenseInfo();

		var licensedLib = generator.doLicensing(library, info, PASSWORD_LIB);

		var json = new File(licensedLib, JSON);
		assertTrue(json.exists());

		var reader = new JsonReader(new FileReader(json));
		var gson = new Gson();
		var mapType = new TypeToken<License>() {}.getType();
		License license = gson.fromJson(reader, mapType);

		var certBytes = license.certificate().getBytes();
		var licenseInfo = LicenseInfo.of(new ByteArrayInputStream(certBytes));
		assertEquals(info, licenseInfo);

		var publicKey = CertUtils.getPublicKey(new ByteArrayInputStream(certBytes));
		var signature = Base64.decode(license.signature());
		assertTrue(SignAgent.verifySignature(library, signature, publicKey));
	}

	private File createTestLibrary()
			throws IOException, URISyntaxException {
		var library = tempFolder.newFolder("library");
		var indexURL = getClass().getResource("index.bin");
		var index = new File(Objects.requireNonNull(indexURL).toURI());

		var indexA = new File(library, "index_A.bin");
		Files.copy(index.toPath(), indexA.toPath());
		var indexB = new File(library, "index_B.bin");
		Files.copy(index.toPath(), indexB.toPath());

		var json = new File(library, "library.json");
		var writer = new BufferedWriter(new FileWriter(json));
		writer.write("{\"name\":\"new_database\",\"version\":\"1.0\"}");
		writer.close();

		return library;
	}

}
