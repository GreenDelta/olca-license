package org.openlca.license.certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import org.openlca.license.Licensor;
import org.openlca.license.TestUtils;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Objects;

import static org.junit.Assert.*;

public class TestCertificateGenerator {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testCreateLicenseCertificate()
			throws Exception {
		var keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGenerator.initialize(2048);
		var keyPairCA = keyPairGenerator.generateKeyPair();
		var certAuth = getTestCertAuth();
		var generator = new CertificateGenerator(certAuth, keyPairCA);
		var info = TestUtils.getExpiredCertificateInfo();
		var keyPair = Licensor.generateKeyPair();
		var certificate = generator.createCertificate(info, keyPair);

		assertNotNull(certificate);

		var expectedKeyUsage = new boolean[9];
		expectedKeyUsage[0] = true;
		assertArrayEquals(expectedKeyUsage, certificate.getKeyUsage());

		var beforeDiff = Math.abs(
				info.notBefore().getTime() - certificate.getNotBefore().getTime());
		assertTrue(beforeDiff < 1000);
		var afterDiff = Math.abs(
				info.notAfter().getTime() - certificate.getNotAfter().getTime());
		assertTrue(afterDiff < 1000);

		var subjectName = certificate.getSubjectX500Principal().getName();
		var subjectPerson = Person.of(subjectName);
		assertEquals(info.subject(), subjectPerson);
	}

	private X509CertificateHolder getTestCertAuth()
			throws URISyntaxException, IOException {
		var certName = "ca.crt";
		var certURL = getClass().getResource(certName);
		var certFile = new File(Objects.requireNonNull(certURL).toURI());

		return CertUtils.getX509CertificateHolder(certFile);
	}

}
