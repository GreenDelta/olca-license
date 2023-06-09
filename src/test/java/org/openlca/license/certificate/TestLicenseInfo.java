package org.openlca.license.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Objects;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


public class TestLicenseInfo {

	@Test
	public void testPersonOf() {
		var rdn = "CN=John Doe,C=DE,E=john.doe@mail.com,O=Green Corp.";
		var x500Name = new X500Name(rdn);
		var personFromX500Name = Person.of(x500Name);
		var personFromString = Person.of(rdn);

		assertEquals("John Doe", personFromX500Name.commonName());
		assertEquals("DE", personFromX500Name.country());
		assertEquals("john.doe@mail.com", personFromX500Name.email());
		assertEquals("Green Corp.", personFromX500Name.organisation());

		assertEquals(personFromString, personFromX500Name);
	}

	@Test
	public void testReadLicense()
			throws URISyntaxException, FileNotFoundException, CertificateException {
		var certName = "test.crt";
		var certURL = getClass().getResource(certName);
		var cert = new File(Objects.requireNonNull(certURL).toURI());
		var license = LicenseInfo.of(cert);

		assertNotNull(license);
		// TODO Add more assertion.
	}

}
