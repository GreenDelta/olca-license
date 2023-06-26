package org.openlca.license;

import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.certificate.Person;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Calendar;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class TestUtils {

	public static final int BUFFER_SIZE = 8192;

	public static CertificateInfo getExpiredCertificateInfo() {
		var calendar = Calendar.getInstance();
		calendar.set(2021, Calendar.JULY, 20, 21, 37, 0);
		var startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		var endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	public static CertificateInfo getValidCertificateInfo() {
		var calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, -1);
		var startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		var endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	public static CertificateInfo getNotYetValidCertificateInfo() {
		var calendar = Calendar.getInstance();
		calendar.add(Calendar.MONTH, 1);
		var startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		var endDate = calendar.getTime();

		return new CertificateInfo(startDate, endDate, getSubject(), getIssuer());
	}

	private static Person getSubject() {
		return new Person("John Doe", "US", "john@green-company.com",
				"Green Company");
	}

	private static Person getIssuer() {
		return new Person("Nexus CA", "DE", "", "Green Delta");
	}



	public static ZipInputStream createTestLibrary(File file) throws IOException,
			URISyntaxException {
		try (var zipOut = new ZipOutputStream(new FileOutputStream(file))) {
			addIndexFile(zipOut, "index_A.bin");
			addIndexFile(zipOut, "index_B.bin");

			addLibraryJson(zipOut);
		}

		return new ZipInputStream(new FileInputStream(file));
	}

	private static void addLibraryJson(
			ZipOutputStream zipOut) throws IOException {
		var json = new File("library.json");
		var writer = new BufferedWriter(new FileWriter(json));
		writer.write("{\"name\":\"new_database\",\"version\":\"1.0\"}");
		writer.close();

		addToZipOut(zipOut, json, json.getName());
		json.delete();
	}

	private static void addIndexFile(ZipOutputStream zipOut, String name)
			throws URISyntaxException, IOException {
		var indexURL = TestUtils.class.getResource("index.bin");
		var index = new File(Objects.requireNonNull(indexURL).toURI());

		addToZipOut(zipOut, index, name);
	}


	public static void addToZipOut(ZipOutputStream zipOut, File file,
			String name) throws IOException {
		var fis = new FileInputStream(file);

		var zipEntry = new ZipEntry(name);
		zipOut.putNextEntry(zipEntry);

		var bytes = new byte[BUFFER_SIZE];
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
			var file = new File(target, entry.getName());

			if (!file.toPath().normalize().startsWith(target.toPath())) {
				throw new IOException("Bad zip entry");
			}

			if (entry.isDirectory()) {
				file.mkdirs();
				continue;
			}

			var buffer = new byte[BUFFER_SIZE];
			file.getParentFile().mkdirs();
			try (var out = new BufferedOutputStream(new FileOutputStream(file))) {
				int count;
				while ((count = zip.read(buffer)) != -1) {
					out.write(buffer, 0, count);
				}
			}

		}
	}

	public static void zip(File source, File zip) throws IOException {
		try (var zos = new ZipOutputStream(new FileOutputStream(zip))) {
			Files.walkFileTree(source.toPath(), new SimpleFileVisitor<>() {
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
						throws IOException {
					var entry = new ZipEntry(source.toPath().relativize(file).toString());
					zos.putNextEntry(entry);
					Files.copy(file, zos);
					zos.closeEntry();
					return FileVisitResult.CONTINUE;
				}
			});
		}
	}

	public static void extractFile(File zip, String fileName,
			FileOutputStream out) throws IOException {
		try (var bis = new BufferedInputStream(new FileInputStream(zip))) {
			var zin = new ZipInputStream(bis);
			ZipEntry ze;
			while ((ze = zin.getNextEntry()) != null) {
				if (ze.getName().equals(fileName)) {
					var buffer = new byte[BUFFER_SIZE];
					int len;
					while ((len = zin.read(buffer)) != -1) {
						out.write(buffer, 0, len);
					}
				}
			}
		}
	}

}
