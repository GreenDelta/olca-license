package org.openlca.license.certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;
import org.openlca.license.TestUtils;

import java.io.IOException;
import java.util.Calendar;
import java.util.Objects;

import static org.junit.Assert.*;


public class TestCertificateInfo {

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
	public void testEqualDate() {
		var i = TestUtils.getExpiredCertificateInfo();

		var calendar = Calendar.getInstance();

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
		var i = TestUtils.getExpiredCertificateInfo();
		// inverting subject and issuer
		assertNotEquals(i, new CertificateInfo(i.notBefore(), i.notAfter(), i.issuer(),
				i.subject()));
	}

	@Test
	public void testEqual() {
		var info1 = TestUtils.getExpiredCertificateInfo();
		var info2 = TestUtils.getExpiredCertificateInfo();
		assertEquals(info1, info2);
	}


	@Test
	public void testReadLicense() throws IOException {
		var certName = "test.crt";
		var certURL = getClass().getResource(certName);
		var info = CertificateInfo.of(Objects.requireNonNull(certURL).openStream());
		var expectedInfo = TestUtils.getExpiredCertificateInfo();

		assertEquals(expectedInfo, info);
	}

	@Test
	public void testValid() throws IOException {
		var certName = "test.crt";
		var certURL = getClass().getResource(certName);
		var info = CertificateInfo.of(Objects.requireNonNull(certURL).openStream());

		assertFalse(info.isValid());
	}

}
