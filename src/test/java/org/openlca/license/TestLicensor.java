package org.openlca.license;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.certificate.CertificateInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Objects;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;
import static org.openlca.license.TestUtils.*;


public class TestLicensor {

	private File ca;
	private static final char[] PASSWORD_LIB = "passlib123".toCharArray();

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void initializeCertificateAuthority() throws URISyntaxException {
		var caURL = getClass().getResource("nexus-ca");
		ca = new File(Objects.requireNonNull(caURL).toURI());
	}

	private File initLibrary(CertificateInfo info) throws IOException,
			URISyntaxException {
		var rawLibrary = tempFolder.newFile("raw.zlib");
		var library = tempFolder.newFile("library.zlib");
		var licensor = Licensor.getInstance(ca);

		try (var input = TestUtils.createTestLibrary(rawLibrary);
				 var output = new ZipOutputStream(new FileOutputStream(library))) {
			licensor.license(input, output, PASSWORD_LIB, info);
		}

		var libraryFolder = tempFolder.newFolder("library");
		try (var zip = new ZipInputStream(new FileInputStream(library))) {
			TestUtils.extract(zip, libraryFolder);
		}
		return libraryFolder;
	}

	@Test
	public void testCreateLicensorInstance() throws IOException {
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
	public void testCertificateInfo() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder);

		var certificateInfo = license.getInfo();
		assertEquals(info, certificateInfo);
	}

	@Test
	public void testSignatureStatus() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);

		// Adding a file to make the signature check fail
		var file = new File(libraryFolder, "file");
		file.createNewFile();

		var license = License.of(libraryFolder);
		var email = info.subject().email();
		var status = license.status(libraryFolder, email, PASSWORD_LIB);
		assertEquals(LicenseStatus.CORRUPTED, status);
	}

	@Test
	public void testExpiredStatus() throws IOException, URISyntaxException {
		var info = getExpiredCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder);

		var email = info.subject().email();
		var status = license.status(libraryFolder, email, PASSWORD_LIB);
		assertEquals(LicenseStatus.EXPIRED, status);
	}

	@Test
	public void testStatusNotYetValid() throws IOException, URISyntaxException {
		var info = getNotYetValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder);

		var email = info.subject().email();
		var status = license.status(libraryFolder, email, PASSWORD_LIB);
		assertEquals(LicenseStatus.NOT_YET_VALID, status);
	}

	@Test
	public void testStatusWrongEmail() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder);

		var email = "wrong email";
		var status = license.status(libraryFolder, email, PASSWORD_LIB);
		assertEquals(LicenseStatus.WRONG_USER, status);
	}

	@Test
	public void testStatusWrongPassword() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder);

		var email = info.subject().email();
		var password = "wrongpassword".toCharArray();
		var status = license.status(libraryFolder, email, password);
		assertEquals(LicenseStatus.WRONG_PASSWORD, status);
	}

	public void testLicenseLibrary() throws IOException {
		var licensor = Licensor.getInstance(ca);
		var info = getExpiredCertificateInfo();

		try (var input = new ZipInputStream(new FileInputStream("agribalib.zip"));
				 var output = new ZipOutputStream(new FileOutputStream("agribalib.zlib"))) {
			licensor.license(input, output, PASSWORD_LIB, info);
		}
	}

}
