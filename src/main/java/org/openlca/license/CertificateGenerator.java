package org.openlca.license;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class CertificateGenerator {

	private final Logger log = LoggerFactory.getLogger(getClass());

	private static final String KEY_ALGORITHM = "RSA";
	private static final String BC_PROVIDER = "BC";
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private final X509CertificateHolder ca;
	private final KeyPair keyPair;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public CertificateGenerator(X509CertificateHolder ca, KeyPair keyPair) {
		this.ca = ca;
		this.keyPair = keyPair;
	}

	public void createCertificate() {
		try {
			// Initialize a new KeyPair generator
			var keyPairGenerator = KeyPairGenerator
					.getInstance(KEY_ALGORITHM, BC_PROVIDER);
			keyPairGenerator.initialize(2048);

			// Setup start date to yesterday and end date for 1 year validity
			var calendar = Calendar.getInstance();
			calendar.add(Calendar.DATE, -1);
			var startDate = calendar.getTime();

			calendar.add(Calendar.YEAR, 1);
			var endDate = calendar.getTime();

			// Generate a new KeyPair and sign it using the CA private key by
			// generating a CSR (Certificate Signing Request)
			var issuedCertSubject = new X500Name("CN=issued-cert");
			var randomLong = new SecureRandom().nextLong();
			var issuedCertSerialNum = new BigInteger(Long.toString(randomLong));
			var issuedCertKeyPair = keyPairGenerator.generateKeyPair();

			var p10Builder = new JcaPKCS10CertificationRequestBuilder(
					issuedCertSubject, issuedCertKeyPair.getPublic());
			var csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
					.setProvider(BC_PROVIDER);

			// Sign the new KeyPair with the CA private key
			var csrContentSigner = csrBuilder.build(keyPair.getPrivate());
			var csr = p10Builder.build(csrContentSigner);

			// Use the signed KeyPair and CSR to generate an issued Certificate
			// Here serial number is randomly generated. In general, CAs use
			// a sequence to generate Serial number and avoid collisions
			var issuedCertBuilder = new X509v3CertificateBuilder(ca.getSubject(),
					issuedCertSerialNum, startDate, endDate, csr.getSubject(),
					csr.getSubjectPublicKeyInfo());

			var issuedCertExtUtils = new JcaX509ExtensionUtils();

			// Add Extensions
			// Use BasicConstraints to say that this certificate is not a CA
			issuedCertBuilder.addExtension(Extension.basicConstraints, true,
					new BasicConstraints(false));

			// Add Issuer cert identifier as Extension
			var rootCert = new JcaX509CertificateConverter().getCertificate(ca);
			var authId = issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert);
			issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
					authId);
			var subjectId = issuedCertExtUtils.createSubjectKeyIdentifier(
					csr.getSubjectPublicKeyInfo());
			issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					subjectId);

			// Add intended key usage extension if needed
			issuedCertBuilder.addExtension(Extension.keyUsage, false,
					new KeyUsage(KeyUsage.keyEncipherment));

			var issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
			var issuedCert = new JcaX509CertificateConverter()
					.setProvider(BC_PROVIDER)
					.getCertificate(issuedCertHolder);

			// Verify the issued cert signature against the CA (issuer) cert
			issuedCert.verify(keyPair.getPublic(), BC_PROVIDER);

			writeCertToFileBase64Encoded(issuedCert, "products/issued-cert.crt");
		} catch (Exception e) {
			log.error("Error while creating the certificate.", e);
		}
	}

	static void writeCertToFileBase64Encoded(X509Certificate certificate,
			String fileName) throws Exception {
		var bytes = certificate.getEncoded();
		try (final var out = new FileOutputStream(fileName)) {
			out.write("-----BEGIN CERTIFICATE-----\n"
					.getBytes(StandardCharsets.US_ASCII));
			out.write(Base64.encode(bytes));
			out.write("\n-----END CERTIFICATE-----"
					.getBytes(StandardCharsets.US_ASCII));
		}
	}

}
