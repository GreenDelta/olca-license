package org.openlca.license;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.openlca.license.TestUtils.getAfterCADateCertificateInfo;
import static org.openlca.license.TestUtils.getAfterDateCertificateInfo;
import static org.openlca.license.TestUtils.getExpiredCertificateInfo;
import static org.openlca.license.TestUtils.getInvertedDateCertificateInfo;
import static org.openlca.license.TestUtils.getMaxEndDateCertificateInfo;
import static org.openlca.license.TestUtils.getNotYetValidCertificateInfo;
import static org.openlca.license.TestUtils.getValidCertificateInfo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.util.Date;
import java.util.Objects;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.access.Credentials;
import org.openlca.license.access.LicenseStatus;
import org.openlca.license.access.Session;
import org.openlca.license.certificate.CertificateInfo;

public class TestLicensor {

	private File ca;
	private static final char[] PASSWORD_LIB = "passlib123".toCharArray();

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void initializeCertificateAuthority() throws URISyntaxException {
		URL caURL = getClass().getResource("nexus-ca");
		ca = new File(Objects.requireNonNull(caURL).toURI());
	}

	private File initLibrary(CertificateInfo info) throws IOException,
			URISyntaxException {
		Licensor licensor = Licensor.getInstance(ca);
		return initLibrary(licensor, info, PASSWORD_LIB);
	}
	
	private File initLibrary(CertificateInfo info, char[] password)
			throws IOException, URISyntaxException {
		Licensor licensor = Licensor.getInstance(ca);
		return initLibrary(licensor, info, password);
	}

	private File initLibrary(Licensor licensor, CertificateInfo info,
			char[] password) throws IOException, URISyntaxException {
		File rawLibrary = tempFolder.newFile("raw.zlib");
		File library = tempFolder.newFile("library.zlib");
		
		try (ZipInputStream input = TestUtils.createTestLibrary(rawLibrary);
				ZipOutputStream output = new ZipOutputStream(new FileOutputStream(library))) {
			licensor.license(input, output, password, info);
		}

		File libraryFolder = tempFolder.newFolder("library");
		try (ZipInputStream zip = new ZipInputStream(new FileInputStream(library))) {
			TestUtils.extract(zip, libraryFolder);
		}
		return libraryFolder;
	}

	@Test
	public void testCreateLicensorInstance() throws IOException {
		Licensor generator = Licensor.getInstance(ca);

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
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);

		assertNotNull(license);
		CertificateInfo certificateInfo = license.getInfo();
		assertEquals(info, certificateInfo);
	}

	@Test
	public void testValidStatus() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
	}

	@Test
	public void testNullPassword() throws IOException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		assertThrows(RuntimeException.class, () -> initLibrary(info, null));
	}

	@Test
	public void testEmptyPassword() throws IOException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		assertThrows(RuntimeException.class, () -> initLibrary(info, "".toCharArray()));
	}

	@Test
	public void testInvertedDate() {
		CertificateInfo info = getInvertedDateCertificateInfo();
		assertThrows(RuntimeException.class, () -> initLibrary(info, null));
	}

	@Test
	public void testAfterCADate() {
		CertificateInfo info = getAfterCADateCertificateInfo();
		assertThrows(RuntimeException.class, () -> initLibrary(info, null));
	}
	
	@Test
	public void testSignatureStatus() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);

		// Adding a file to make the signature check fail
		File file = new File(libraryFolder, "file");
		file.createNewFile();

		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.CORRUPTED, status);
	}

	@Test
	public void testExpiredStatus() throws IOException, URISyntaxException {
		CertificateInfo info = getExpiredCertificateInfo();
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.EXPIRED, status);
	}
	
	@Test
	public void testMaxEndDate() throws IOException, URISyntaxException {
		Licensor licensor = Licensor.getInstance(ca);
		CertificateInfo info = getMaxEndDateCertificateInfo(licensor);
		File libraryFolder = initLibrary(licensor, info, PASSWORD_LIB);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
		Date expectedEndDate = licensor.getCertificateAuthority().getNotAfter();
		assertEquals(license.getInfo().notAfter(), expectedEndDate);
	}

	@Test
	public void testOverEndDate() throws IOException, URISyntaxException {
		Licensor licensor = Licensor.getInstance(ca);
		CertificateInfo info = getAfterDateCertificateInfo(licensor);
		File libraryFolder = initLibrary(licensor, info, PASSWORD_LIB);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
		Date expectedEndDate = licensor.getCertificateAuthority().getNotAfter();
		assertEquals(license.getInfo().notAfter(), expectedEndDate);
	}


	@Test
	public void testStatusNotYetValid() throws IOException, URISyntaxException {
		CertificateInfo info = getNotYetValidCertificateInfo();
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.NOT_YET_VALID, status);
	}

	@Test
	public void testStatusWrongEmail() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = "wrong email";
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.WRONG_USER, status);
	}

	@Test
	public void testStatusUserName() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String userName = info.subject().userName();
		Credentials credentials = new Credentials(userName, PASSWORD_LIB);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.VALID, status);
	}

	@Test
	public void testStatusWrongPassword() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		char[] password = "wrongpassword".toCharArray();
		Credentials credentials = new Credentials(email, password);
		LicenseStatus status = license.status(libraryFolder, credentials);
		assertEquals(LicenseStatus.WRONG_PASSWORD, status);
	}

	@Test
	public void testGetCipherFromCredentials() throws IOException,
			URISyntaxException, BadPaddingException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		Cipher cipher = license.getDecryptCipher(credentials);
		File encryptedFile = new File(libraryFolder, "index_A.enc");
		File decryptedFile = new File(libraryFolder, "index_A.bin");

		try (FileInputStream in = new FileInputStream(encryptedFile);
				FileOutputStream out = new FileOutputStream(decryptedFile)) {
			Crypto.doCrypto(cipher, in, out);
		}
		URL indexURL = TestUtils.class.getResource("index.bin");
		File index = new File(Objects.requireNonNull(indexURL).toURI());

		assertArrayEquals(Files.readAllBytes(index.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	@Test
	public void testGetCipherFromSecret() throws IOException,
			URISyntaxException, BadPaddingException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);
		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		Session session = license.createSession(credentials);
		assertNotNull(session);

		Cipher cipher = license.getDecryptCipher(session);
		File encryptedFile = new File(libraryFolder, "index_A.enc");
		File decryptedFile = new File(libraryFolder, "index_A.bin");

		try (FileInputStream in = new FileInputStream(encryptedFile);
				FileOutputStream out = new FileOutputStream(decryptedFile)) {
			Crypto.doCrypto(cipher, in, out);
		}
		URL indexURL = TestUtils.class.getResource("index.bin");
		File index = new File(Objects.requireNonNull(indexURL).toURI());

		assertArrayEquals(Files.readAllBytes(index.toPath()),
				Files.readAllBytes(decryptedFile.toPath()));
	}

	@Test
	public void testStatusFromSession() throws IOException, URISyntaxException {
		CertificateInfo info = getValidCertificateInfo(Licensor.getInstance(ca));
		File libraryFolder = initLibrary(info);

		License license = License.of(libraryFolder).orElse(null);
		assertNotNull(license);

		String email = info.subject().email();
		Credentials credentials = new Credentials(email, PASSWORD_LIB);
		Session session = license.createSession(credentials);
		LicenseStatus status = license.status(libraryFolder, session);
		assertEquals(LicenseStatus.VALID, status);
	}

}
