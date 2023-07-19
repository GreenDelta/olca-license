package org.openlca.license.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import java.net.URL;
import java.util.Calendar;
import java.util.Objects;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;
import org.openlca.license.TestUtils;


public class TestCertificateInfo {

	@Test
	public void testPersonOf() {
		String rdn = "CN=John Doe,C=DE,E=john.doe@mail.com,O=Green Corp.";
		X500Name x500Name = new X500Name(rdn);
		Person personFromX500Name = Person.of(x500Name);
		Person personFromString = Person.of(rdn);

		assertEquals("John Doe", personFromX500Name.commonName());
		assertEquals("DE", personFromX500Name.country());
		assertEquals("john.doe@mail.com", personFromX500Name.email());
		assertEquals("Green Corp.", personFromX500Name.organisation());

		assertEquals(personFromString, personFromX500Name);
	}

	@Test
	public void testEqualDate() {
		CertificateInfo i = TestUtils.getExpiredCertificateInfo();

		Calendar calendar = Calendar.getInstance();

		calendar.setTime(i.notBefore());
		calendar.add(Calendar.YEAR, 1);
		assertNotEquals(i, new CertificateInfo(calendar.getTime(), i.notAfter(),
				i.subject(), i.issuer()));

		calendar.setTime(i.notAfter());
		calendar.add(Calendar.MINUTE, 1);
		assertNotEquals(i, new CertificateInfo(i.notBefore(), calendar.getTime(),
				i.subject(), i.issuer()));

		calendar.setTime(i.notAfter());
		calendar.add(Calendar.MILLISECOND, 1);
		assertEquals(i, new CertificateInfo(i.notBefore(), calendar.getTime(),
				i.subject(), i.issuer()));
	}

	@Test
	public void testEqualPeople() {
		CertificateInfo i = TestUtils.getExpiredCertificateInfo();
		// inverting subject and issuer
		assertNotEquals(i, new CertificateInfo(i.notBefore(), i.notAfter(), i.issuer(),
				i.subject()));
	}

	@Test
	public void testEqual() {
		CertificateInfo info1 = TestUtils.getExpiredCertificateInfo();
		CertificateInfo info2 = TestUtils.getExpiredCertificateInfo();
		assertEquals(info1, info2);
	}


	@Test
	public void testReadLicense() throws IOException {
		String certName = "test.crt";
		URL certURL = getClass().getResource(certName);
		CertificateInfo info = CertificateInfo.of(Objects.requireNonNull(certURL).openStream());
		CertificateInfo expectedInfo = TestUtils.getExpiredCertificateInfo();

		assertEquals(expectedInfo, info);
	}

	@Test
	public void testValid() throws IOException {
		String certName = "test.crt";
		URL certURL = getClass().getResource(certName);
		CertificateInfo info = CertificateInfo.of(Objects.requireNonNull(certURL).openStream());

		assertFalse(info.isValid());
	}

}
