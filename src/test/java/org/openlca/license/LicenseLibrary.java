package org.openlca.license;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Objects;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.openlca.license.certificate.Person;

public class LicenseLibrary {

	private static final char[] PASSWORD_LIB = "password".toCharArray();

	private static final String INPUT = "input.zip";

	private static final String OUTPUT = "output.zip";

	private static final Person SUBJECT =
			new Person("john", "John Doe", "DE", "john.doe@example.com",
					"John Doe GmbH");

	private static final Date NOT_BEFORE = new Date();

	private static final Date NOT_AFTER = new Date();

	public void license() throws IOException, URISyntaxException {
		var caURL = getClass().getResource("nexus-ca");
		var ca = new File(Objects.requireNonNull(caURL).toURI());
		var licensor = Licensor.getInstance(ca);

		var info = licensor.createCertificateInfo(NOT_BEFORE, NOT_AFTER, SUBJECT);

		var library = new File(OUTPUT);
		try (var input = new ZipInputStream(new FileInputStream(INPUT));
				 var output = new ZipOutputStream(new FileOutputStream(library))) {
			licensor.license(input, output, PASSWORD_LIB, info);
		}
	}


	public static void main(String[] args) {
		var licenseLibrary = new LicenseLibrary();
		try {
			licenseLibrary.license();
		} catch (IOException | URISyntaxException e) {
			e.printStackTrace();
		}
	}
}
