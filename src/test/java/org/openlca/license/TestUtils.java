package org.openlca.license;

import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.certificate.Person;

public class TestUtils {

	public static final int BUFFER_SIZE = 8_192;

	public static CertificateInfo getExpiredCertificateInfo() {
		Calendar calendar = Calendar.getInstance();
		calendar.set(2021, Calendar.JULY, 20, 21, 37, 0);
		Date startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		Date endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	public static CertificateInfo getValidCertificateInfo() {
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, -1);
		Date startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		Date endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	public static CertificateInfo getNotYetValidCertificateInfo() {
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, 1);
		Date startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		Date endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	static Person getSubject() {
		return new Person("John Doe", "US", "john@green-company.com",
				"Green Company");
	}

	static Person getIssuer() {
		return new Person("Nexus CA", "DE", "", "Green Delta");
	}

	public static ZipInputStream createTestLibrary(File file) throws IOException,
			URISyntaxException {
		try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(file))) {
			addIndexFile(zipOut, "index_A.bin");
			addIndexFile(zipOut, "index_B.bin");

			addLibraryJson(zipOut);
		}

		return new ZipInputStream(new FileInputStream(file));
	}

	private static void addLibraryJson(
			ZipOutputStream zipOut) throws IOException {
		File json = new File("library.json");
		BufferedWriter writer = new BufferedWriter(new FileWriter(json));
		writer.write("{\"libName\":\"new_database\",\"version\":\"1.0\"}");
		writer.close();

		addToZipOut(zipOut, json, json.getName());
		json.delete();
	}

	private static void addIndexFile(ZipOutputStream zipOut, String name)
			throws URISyntaxException, IOException {
		URL indexURL = TestUtils.class.getResource("index.bin");
		File index = new File(Objects.requireNonNull(indexURL).toURI());

		addToZipOut(zipOut, index, name);
	}


	public static void addToZipOut(ZipOutputStream zipOut, File file,
			String name) throws IOException {
		FileInputStream fis = new FileInputStream(file);

		ZipEntry zipEntry = new ZipEntry(name);
		zipOut.putNextEntry(zipEntry);

		byte[] bytes = new byte[BUFFER_SIZE];
		int length;
		while ((length = fis.read(bytes)) >= 0) {
			zipOut.write(bytes, 0, length);
		}
		fis.close();
	}

	public static void extract(ZipInputStream zip, File target)
			throws IOException {
		ZipEntry entry;
		while ((entry = zip.getNextEntry()) != null) {
			File file = new File(target, entry.getName());

			if (!file.toPath().normalize().startsWith(target.toPath())) {
				throw new IOException("Bad zip entry");
			}

			if (entry.isDirectory()) {
				file.mkdirs();
				continue;
			}

			byte[] buffer = new byte[BUFFER_SIZE];
			file.getParentFile().mkdirs();
			try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(file))) {
				int count;
				while ((count = zip.read(buffer)) != -1) {
					out.write(buffer, 0, count);
				}
			}

		}
	}

	public static void zip(File source, File zip) throws IOException {
		try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zip))) {
			Files.walkFileTree(source.toPath(), new SimpleFileVisitor<Path>() {
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					ZipEntry entry = new ZipEntry(source.toPath().relativize(file).toString());
					zos.putNextEntry(entry);
					Files.copy(file, zos);
					zos.closeEntry();
					return FileVisitResult.CONTINUE;
				}
			});
		}
	}

}
