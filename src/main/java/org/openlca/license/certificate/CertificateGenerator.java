package org.openlca.license.certificate;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateGenerator {

	private static final String BC = "BC";
	private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	private static final String BEGIN = "-----BEGIN CERTIFICATE-----\n";
	private static final String END = "\n-----END CERTIFICATE-----";
	private final X509CertificateHolder certAuth;
	private final KeyPair keyPairCA;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private ContentSigner csrContentSigner;

	public CertificateGenerator(X509CertificateHolder certAuth, KeyPair keyPair) {
		this.certAuth = certAuth;
		this.keyPairCA = keyPair;
	}

	public X509Certificate createCertificate(LicenseInfo info, KeyPair keyPair)
			throws CertificateException {
		try {
			var csr = createCSR(info, keyPair.getPublic());
			var certBuilder = getCertBuilder(info, csr);

			addExtensions(certBuilder, csr);

			var issuedCertHolder = certBuilder.build(csrContentSigner);
			var issuedCert = new JcaX509CertificateConverter()
					.setProvider(BC)
					.getCertificate(issuedCertHolder);

			// Verify the issued cert signature against the CA (issuer) cert
			issuedCert.verify(keyPairCA.getPublic(), BC);

			return issuedCert;
		} catch (NoSuchAlgorithmException | InvalidKeyException |
						 NoSuchProviderException | SignatureException e) {
			throw new CertificateException("Error while creating the license "
					+ "certificate", e);
		}
	}

	private void addExtensions(X509v3CertificateBuilder certBuilder,
			PKCS10CertificationRequest csr) throws CertificateException {
		try {
			var extensionUtils = new JcaX509ExtensionUtils();

			// Use BasicConstraints to say that this certificate is not a CA
			certBuilder.addExtension(Extension.basicConstraints, true,
					new BasicConstraints(false));

			// Add issuer certificate identifier as Extension
			var certCA = new JcaX509CertificateConverter().getCertificate(certAuth);
			var authId = extensionUtils.createAuthorityKeyIdentifier(certCA);
			var keyIdCA = Extension.authorityKeyIdentifier;
			certBuilder.addExtension(keyIdCA, false, authId);
			var subjectId = extensionUtils.createSubjectKeyIdentifier(
					csr.getSubjectPublicKeyInfo());
			var keyIdSubject = Extension.subjectKeyIdentifier;
			certBuilder.addExtension(keyIdSubject, false, subjectId);

			// Add intended key usage extension if needed
			var keyUsage = new KeyUsage(KeyUsage.digitalSignature);
			certBuilder.addExtension(Extension.keyUsage, false, keyUsage);
		} catch (CertificateException | NoSuchAlgorithmException
						 | CertIOException e) {
			throw new CertificateException("Error while adding extension to the "
					+ "certificate", e);
		}
	}

	private ContentSigner getCsrContentSigner() throws CertificateException {
		try {
		if (csrContentSigner == null) {
			var csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
			csrBuilder.setProvider(BC);

			// Sign the new KeyPair with the CA private key
			csrContentSigner = csrBuilder.build(keyPairCA.getPrivate());
		}
		return csrContentSigner;
		} catch (OperatorCreationException e) {
			throw new CertificateException("Error while getting ContentSigner for "
					+ "the CSR", e);
		}

	}

	private X509v3CertificateBuilder getCertBuilder(LicenseInfo info,
			PKCS10CertificationRequest csr) {
		var randomLong = new SecureRandom().nextLong();
		var issuedCertSerialNum = new BigInteger(Long.toString(randomLong));

		// Use the signed KeyPair and CSR to generate an issued Certificate
		// Here serial number is randomly generated. In general, CAs use
		// a sequence to generate Serial number and avoid collisions
		return new X509v3CertificateBuilder(
				certAuth.getSubject(), issuedCertSerialNum, info.notBefore(),
				info.notAfter(), csr.getSubject(), csr.getSubjectPublicKeyInfo());
	}

	private PKCS10CertificationRequest createCSR(LicenseInfo info, PublicKey key)
			throws CertificateException {
		var subject = info.subject().asX500Name();
		var p10Builder = new JcaPKCS10CertificationRequestBuilder(subject, key);
		return p10Builder.build(getCsrContentSigner());
	}

	public static String toBase64(X509Certificate certificate)
			throws CertificateEncodingException {
		var bytes = certificate.getEncoded();
		return BEGIN + new String(Base64.encode(bytes)) + END;
	}

}
