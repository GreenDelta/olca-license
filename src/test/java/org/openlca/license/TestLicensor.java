package org.openlca.license;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.certificate.CertUtils;
import org.openlca.license.certificate.LicenseInfo;
import org.openlca.license.signature.Verifier;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;
import static org.openlca.license.Licensor.JSON;
import static org.openlca.license.TestUtils.getTestLicenseInfo;


public class TestLicensor {

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
		var generator = Licensor.getInstance(ca);

		assertNotNull(generator);
		assertNotNull(generator.certAuthority);
		assertNotNull(generator.publicKeyCA);
		assertNotNull(generator.privateKeyCA);
		assertTrue(generator.certAuthority.isValidOn(new Date()));
		assertEquals("RSA", generator.publicKeyCA.getAlgorithm());
		assertEquals("RSA", generator.privateKeyCA.getAlgorithm());
	}

	@Test
	public void testCreateLicensedLibrary() throws IOException,
			URISyntaxException {
		var rawLibrary = tempFolder.newFile("raw.zlib");
		var library = tempFolder.newFile("library.zlib");

		var info = getTestLicenseInfo();

		try (var input = TestUtils.createTestLibrary(rawLibrary);
				 var output = new ZipOutputStream(new FileOutputStream(library))) {
			var licensor = Licensor.getInstance(ca);
			licensor.license(input, output, PASSWORD_LIB, info);
		}

		var libraryFolder = tempFolder.newFolder("library");
		try (var zip = new ZipInputStream(new FileInputStream(library))) {
			TestUtils.extract(zip, libraryFolder);
		}

		var json = new File(libraryFolder, JSON);
		TestUtils.extractFile(library, JSON, new FileOutputStream(json));
		assertTrue(json.exists());

		var reader = new JsonReader(new FileReader(json));
		var gson = new Gson();
		var mapType = new TypeToken<License>() {}.getType();
		License license = gson.fromJson(reader, mapType);

		var certBytes = license.certificate().getBytes();
		var licenseInfo = LicenseInfo.of(new ByteArrayInputStream(certBytes));
		assertEquals(info, licenseInfo);

		var publicKey = CertUtils.getPublicKey(new ByteArrayInputStream(certBytes));
		var signatures = license.signaturesAsBytes();
		var signAgent = new Verifier(publicKey, signatures);

		List<Path> blackList = new ArrayList<>();
		blackList.add(json.toPath());
		assertTrue(signAgent.verify(libraryFolder, blackList));
	}

}
