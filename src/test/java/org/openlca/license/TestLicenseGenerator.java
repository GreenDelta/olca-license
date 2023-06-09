package org.openlca.license;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.certificate.CertificateGenerator;
import org.openlca.license.certificate.LicenseInfo;
import org.openlca.license.certificate.Person;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.Objects;

import static org.junit.Assert.*;
import static org.openlca.license.LicenseGenerator.*;
import static org.openlca.license.TestUtils.getTestLicenseInfo;


public class TestLicenseGenerator {

	private File ca;
	private static final String PASSWORD_LIB = "passlib123";
	private static final String PASSWORD_CA = "passca123";

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Before
	public void initializeCertificateAuthority()
			throws IOException, LicenseException, CertificateException,
			OperatorCreationException, NoSuchAlgorithmException {
		ca = tempFolder.newFolder("ca");
		var caSubject = getTestLicenseInfo().issuer();
		CertificateAuthority.create(ca, caSubject);
	}

	@Test
	public void testCreateLicenseGeneratorInstance()
			throws IOException, OperatorCreationException, PKCSException {
		var generator = LicenseGenerator.getInstance(ca);

		assertNotNull(generator);
		assertNotNull(generator.certAuthority);
		assertNotNull(generator.publicKeyCA);
		assertNotNull(generator.privateKeyCA);
		assertTrue(generator.certAuthority.isValidOn(new Date()));
		assertEquals("RSA", generator.publicKeyCA.getAlgorithm());
		assertEquals("RSA", generator.privateKeyCA.getAlgorithm());
	}

	@Test
	public void testCreateLicensedLibrary() throws Exception {
		var generator = LicenseGenerator.getInstance(ca);
		var library = createTestLibrary();
		var info = getTestLicenseInfo();
		var licensedLib = generator.doLicensing(library, info, PASSWORD_LIB);

		var certFile = new File(licensedLib, CERT_FILE);
		assertTrue(certFile.exists());

		var licenseInfo = LicenseInfo.of(certFile);
		assertEquals(info, licenseInfo);

		var saltFile = new File(licensedLib, SALT_FILE);
		assertTrue(saltFile.exists());

		var signFile = new File(licensedLib, SIGN_FILE);
		assertTrue(signFile.exists());
	}

	private File createTestLibrary()
			throws IOException, URISyntaxException {
		var library = tempFolder.newFolder("library");
		var indexURL = getClass().getResource("index.bin");
		var index = new File(Objects.requireNonNull(indexURL).toURI());

		var indexA = new File(library, "index_A.bin");
		Files.copy(index.toPath(), indexA.toPath());
		var indexB = new File(library, "index_B.bin");
		Files.copy(index.toPath(), indexB.toPath());

		var writer = new BufferedWriter(new FileWriter("library.json"));
		writer.write("{\"name\":\"new_database\",\"version\":\"1.0\"}");
		writer.close();

		return library;
	}

	private static class CertificateAuthority {

		public static void create(File folder, Person subject)
				throws LicenseException, OperatorCreationException,
				CertificateException, IOException, NoSuchAlgorithmException {
			createCA(folder, subject);
			addPasswordFile(folder);
		}

		public static void createCA(File folder, Person subject)
				throws OperatorCreationException, CertificateException,
				LicenseException, NoSuchAlgorithmException, IOException {
			var keyPair = LicenseGenerator.generateKeyPair();
			storePrivateKey(folder, keyPair.getPrivate());

			var cal = Calendar.getInstance();
			cal.add(Calendar.YEAR, 1);

			var publicKey = keyPair.getPublic().getEncoded();
			var bcPk = SubjectPublicKeyInfo.getInstance(publicKey);

			var certGen = new X509v1CertificateBuilder(
					new X500Name("CN=Root CA Cert"),
					BigInteger.ONE,
					new Date(),
					cal.getTime(),
					subject.asX500Name(),
					bcPk
			);

			var certHolder = certGen.build(
					new JcaContentSignerBuilder("SHA1withRSA")
							.build(keyPair.getPrivate()));
			var certCA = new JcaX509CertificateConverter().getCertificate(certHolder);
			CertificateGenerator.writeCertToBase64(certCA, folder, "ca.crt");
		}

		private static void storePrivateKey(File folder, PrivateKey key)
				throws IOException, OperatorCreationException {
			var privateFolder = new File(folder, "private");
			assertTrue(privateFolder.mkdir());
			var keyFile = new File(privateFolder, "ca.key");

			var sw = new StringWriter();
			try (var pemWriter = new JcaPEMWriter(sw)) {
				var encryptor = new JceOpenSSLPKCS8EncryptorBuilder(
						PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
						.setProvider("BC")
						.setPassword(PASSWORD_CA.toCharArray())
						.build();

				var gen = new JcaPKCS8Generator(key, encryptor);
				pemWriter.writeObject(gen);
			}
			Files.write(keyFile.toPath(), sw.toString().getBytes());
		}

		public static void addPasswordFile(File folder) throws IOException {
			var pass = new File(folder, folder.getName() + ".pass");
			var fileWriter = new FileWriter(pass);
			fileWriter.write(PASSWORD_CA);
			fileWriter.close();
		}

	}

}
