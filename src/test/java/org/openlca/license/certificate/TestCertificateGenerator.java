package org.openlca.license.certificate;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.junit.Test;
import org.openlca.license.Licensor;
import org.openlca.license.TestUtils;

public class TestCertificateGenerator {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testCreateLicenseCertificate()
			throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048);
		KeyPair keyPairCA = keyPairGenerator.generateKeyPair();
		X509CertificateHolder certAuth = getTestCertAuth();
		CertificateGenerator generator = new CertificateGenerator(certAuth, keyPairCA);
		CertificateInfo info = TestUtils.getExpiredCertificateInfo();
		KeyPair keyPair = Licensor.generateKeyPair();
		X509Certificate certificate = generator.createCertificate(info, keyPair);

		assertNotNull(certificate);

		boolean[] expectedKeyUsage = new boolean[9];
		expectedKeyUsage[0] = true;
		assertArrayEquals(expectedKeyUsage, certificate.getKeyUsage());

		long beforeDiff = Math.abs(
				info.notBefore().getTime() - certificate.getNotBefore().getTime());
		assertTrue(beforeDiff < 1000);
		long afterDiff = Math.abs(
				info.notAfter().getTime() - certificate.getNotAfter().getTime());
		assertTrue(afterDiff < 1000);

		String subjectName = certificate.getSubjectX500Principal().getName();
		Person subjectPerson = Person.of(subjectName);
		assertEquals(info.subject(), subjectPerson);
	}

	private X509CertificateHolder getTestCertAuth()
			throws URISyntaxException, IOException {
		String certName = "ca.crt";
		URL certURL = getClass().getResource(certName);
		File certFile = new File(Objects.requireNonNull(certURL).toURI());

		PEMParser parser = Licensor.getPEMParser(certFile);
		return  (X509CertificateHolder) parser.readObject();
	}

}
