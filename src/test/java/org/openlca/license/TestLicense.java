package org.openlca.license;

import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Objects;

import static org.junit.Assert.*;

public class TestLicense {

	@Test
	public void testReadLicense() throws URISyntaxException, FileNotFoundException, CertificateException {
		var certName = "test.crt";
		var certURL = getClass().getResource(certName);
		var cert = new File(Objects.requireNonNull(certURL).toURI());
		var license = License.of(cert);

		assertNotNull(license);
		// TODO Add more assertion.
	}

}
