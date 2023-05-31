package org.openlca.license;

import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertNotNull;

public class TestLicenseGenerator {

	@Test
	public void testCreateCA() {
		new LicenseGenerator();
		var certificate = new File("outputs/issued-cert.crt");
		assertNotNull(certificate);
		assert certificate.exists();
		// TODO add more tests
	}

}
