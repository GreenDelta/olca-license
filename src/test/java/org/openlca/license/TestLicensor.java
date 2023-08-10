package org.openlca.license;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.access.Credentials;
import org.openlca.license.access.LicenseStatus;
import org.openlca.license.certificate.CertificateInfo;

import javax.crypto.BadPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
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
		var licensor = Licensor.getInstance(ca);
		return initLibrary(licensor, info, PASSWORD_LIB);
	}

	private File initLibrary(CertificateInfo info, char[] password)
			throws IOException, URISyntaxException {
		var licensor = Licensor.getInstance(ca);
		return initLibrary(licensor, info, password);
	}

	private File initLibrary(Licensor licensor, CertificateInfo info,
		  char[] password)	throws IOException, URISyntaxException {
		var rawLibrary = tempFolder.newFile("raw.zlib");
		var library = tempFolder.newFile("library.zlib");

		try (var input = TestUtils.createTestLibrary(rawLibrary);
				 var output = new ZipOutputStream(new FileOutputStream(library))) {
			licensor.license(input, output, password, info);
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
		var license = License.of(libraryFolder).orElse(null);

		assertNotNull(license);
		var certificateInfo = license.getInfo();
		assertEquals(info, certificateInfo);
	}

	@Test
	public void testValidStatus() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
	}

	@Test
	public void testNullPassword() {
		var info = getValidCertificateInfo();
		assertThrows(RuntimeException.class, () -> initLibrary(info, null));
	}

	@Test
	public void testEmptyPassword() {
		var info = getValidCertificateInfo();
		assertThrows(RuntimeException.class, () -> initLibrary(info, "".toCharArray()));
	}

	@Test
	public void testInvertedDate() {
		var info = getInvertedDateCertificateInfo();
		assertThrows(RuntimeException.class,
				() -> initLibrary(info, null));
	}

	@Test
	public void testAfterCADate() {
		var info = getAfterCADateCertificateInfo();
		assertThrows(RuntimeException.class, () -> initLibrary(info, null));
	}

	@Test
	public void testSignatureStatus() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);

		// Adding a file to make the signature check fail
		var file = new File(libraryFolder, "file");
		file.createNewFile();

		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.CORRUPTED, status);
	}

	@Test
	public void testExpiredStatus() throws IOException, URISyntaxException {
		var info = getExpiredCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.EXPIRED, status);
	}

	@Test
	public void testMaxEndDate() throws IOException, URISyntaxException {
		var licensor = Licensor.getInstance(ca);
		var info = getMaxEndDateCertificateInfo(licensor);
		var libraryFolder = initLibrary(licensor, info, PASSWORD_LIB);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
		var expectedEndDate = licensor.getCertificateAuthority().getNotAfter();
		assertEquals(license.getInfo().notAfter(), expectedEndDate);
	}

	@Test
	public void testOverEndDate() throws IOException, URISyntaxException {
		var licensor = Licensor.getInstance(ca);
		var info = getAfterDateCertificateInfo(licensor);
		var libraryFolder = initLibrary(licensor, info, PASSWORD_LIB);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
		var expectedEndDate = licensor.getCertificateAuthority().getNotAfter();
		assertEquals(license.getInfo().notAfter(), expectedEndDate);
	}

	@Test
	public void testStatusNotYetValid() throws IOException, URISyntaxException {
		var info = getNotYetValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.NOT_YET_VALID, status);
	}

	@Test
	public void testStatusWrongEmail() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = "wrong email";
		var credentials = new Credentials(email, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.WRONG_USER, status);
	}

	@Test
	public void testStatusUserName() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var userName = info.subject().userName();
		var credentials = new Credentials(userName, PASSWORD_LIB);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
	}

	@Test
	public void testStatusWrongPassword() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var password = "wrongpassword".toCharArray();
		var credentials = new Credentials(email, password);
		var status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.WRONG_PASSWORD, status);
	}

	@Test
	public void testGetCipherFromCredentials() throws IOException,
			URISyntaxException, BadPaddingException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var cipher = license.getDecryptCipher(credentials);
		var encryptedFile = new File(libraryFolder, "index_A.enc");
		var decryptedFile = new File(libraryFolder, "index_A.bin");

		try (var in = new FileInputStream(encryptedFile);
				 var out = new FileOutputStream(decryptedFile)) {
			Crypto.doCrypto(cipher, in, out);
		}
		var indexURL = TestUtils.class.getResource("index.bin");
		var index = new File(Objects.requireNonNull(indexURL).toURI());

		assertArrayEquals(Files.readAllBytes(index.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	@Test
	public void testGetCipherFromSecret() throws IOException,
			URISyntaxException, BadPaddingException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);
		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var session = license.createSession(credentials);
		assertNotNull(session);

		var cipher = license.getDecryptCipher(session);
		var encryptedFile = new File(libraryFolder, "index_A.enc");
		var decryptedFile = new File(libraryFolder, "index_A.bin");

		try (var in = new FileInputStream(encryptedFile);
				 var out = new FileOutputStream(decryptedFile)) {
			Crypto.doCrypto(cipher, in, out);
		}
		var indexURL = TestUtils.class.getResource("index.bin");
		var index = new File(Objects.requireNonNull(indexURL).toURI());

		assertArrayEquals(Files.readAllBytes(index.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	@Test
	public void testStatusFromSession() throws IOException, URISyntaxException {
		var info = getValidCertificateInfo();
		var libraryFolder = initLibrary(info);

		var license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		var email = info.subject().email();
		var credentials = new Credentials(email, PASSWORD_LIB);
		var session = license.createSession(credentials);
		var status = license.status(libraryFolder, session);
		assertEquals(LicenseStatus.VALID, status);
	}

}
