package org.openlca.license;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.access.Credentials;
import org.openlca.license.access.LicenseStatus;
import org.openlca.license.certificate.Person;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.*;

/// Tests for edge cases that resulted in errors before.
public class TestLicenseEdgeCases {

	private static final char[] PASSWORD = "passlib123".toCharArray();

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	private Licensor licensor;
	private byte[] index;

	@Before
	public void setup() throws Exception {
		var caURL = getClass().getResource("nexus-ca");
		var ca = new File(Objects.requireNonNull(caURL).toURI());
		licensor = Licensor.getInstance(ca);
		var indexURL = getClass().getResource("index.bin");
		index = Files.readAllBytes(
				new File(Objects.requireNonNull(indexURL).toURI()).toPath());
	}

	/// The username and email address of a subject can be the same. Before,
	/// this resulted in an `IllegalArgumentException` from `Set.of(..)`.
	@Test
	public void testUserNameEqualsEmail() throws IOException {
		var email = "john@green-company.com";
		var subject = new Person(email, "John Doe", "US", email, "Green Company");
		var library = createLibrary(subject, defaultEntries());
		var license = License.of(library).orElseThrow();

		var credentials = new Credentials(email, PASSWORD);
		assertEquals(LicenseStatus.VALID, license.status(library, credentials));

		var session = license.createSession(credentials);
		assertNotNull(session);
		assertEquals(LicenseStatus.VALID, license.status(library, session));

		var wrong = new Credentials("jane@green-company.com", PASSWORD);
		assertEquals(LicenseStatus.WRONG_USER, license.status(library, wrong));
	}

	/// Checking the password must not write the decrypted index to a temporary
	/// file. Before, each status check left such a file with the decrypted
	/// data in the temp folder.
	@Test
	public void testStatusWritesNoTempFiles() throws IOException {
		var library = createLibrary(subject(), defaultEntries());
		var license = License.of(library).orElseThrow();
		var credentials = new Credentials("john", PASSWORD);

		var before = countTempFiles();
		for (int i = 0; i < 3; i++) {
			assertEquals(LicenseStatus.VALID, license.status(library, credentials));
		}
		assertEquals(LicenseStatus.WRONG_PASSWORD, license.status(
				library, new Credentials("john", "wrong-pass".toCharArray())));
		assertEquals(before, countTempFiles());
	}

	/// Directory entries and names shorter than `.bin` must not fail, and only
	/// `.bin` files with an index name are encrypted.
	@Test
	public void testDirectoryAndShortEntries() throws IOException {
		var entries = defaultEntries();
		entries.put("a/", null);
		entries.put("x", "short".getBytes(StandardCharsets.UTF_8));
		entries.put("index_B.xyz", index);
		var library = createLibrary(subject(), entries);

		assertTrue(new File(library, "index_A.enc").exists());
		assertFalse(new File(library, "index_A.bin").exists());
		assertTrue(new File(library, "a").isDirectory());
		assertTrue(new File(library, "x").exists());

		// not an index because of the extension
		var other = new File(library, "index_B.xyz");
		assertTrue(other.exists());
		assertArrayEquals(index, Files.readAllBytes(other.toPath()));

		var license = License.of(library).orElseThrow();
		assertEquals(LicenseStatus.VALID,
				license.status(library, new Credentials("john", PASSWORD)));
	}

	private Person subject() {
		return new Person("john", "John Doe", "US", "john@green-company.com",
				"Green Company");
	}

	private Map<String, byte[]> defaultEntries() {
		var entries = new LinkedHashMap<String, byte[]>();
		entries.put("library.json",
				"{\"name\":\"test\",\"version\":\"1.0\"}".getBytes(StandardCharsets.UTF_8));
		entries.put("index_A.bin", index);
		return entries;
	}

	/// Creates a library with the given ZIP entries, licenses it, and extracts
	/// it into a folder. Entries with a `null` value are directories.
	private File createLibrary(Person subject, Map<String, byte[]> entries)
			throws IOException {
		var raw = tempFolder.newFile();
		try (var zip = new ZipOutputStream(new FileOutputStream(raw))) {
			for (var e : entries.entrySet()) {
				zip.putNextEntry(new ZipEntry(e.getKey()));
				if (e.getValue() != null) {
					zip.write(e.getValue());
				}
				zip.closeEntry();
			}
		}

		var calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, -1);
		var info = licensor.createCertificateInfo(calendar.getTime(), subject);

		var licensed = tempFolder.newFile();
		try (var input = new ZipInputStream(new FileInputStream(raw));
				 var output = new ZipOutputStream(new FileOutputStream(licensed))) {
			licensor.license(input, output, PASSWORD, info);
		}

		var folder = tempFolder.newFolder();
		try (var zip = new ZipInputStream(new FileInputStream(licensed))) {
			TestUtils.extract(zip, folder);
		}
		return folder;
	}

	private long countTempFiles() {
		var dir = new File(System.getProperty("java.io.tmpdir"));
		var files = dir.listFiles(
				(d, name) -> name.startsWith("out") && name.endsWith(".tmp"));
		return files != null ? files.length : 0;
	}
}
