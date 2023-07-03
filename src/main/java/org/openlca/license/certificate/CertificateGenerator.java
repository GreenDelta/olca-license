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

/**
 * <p>
 *   The {@link CertificateGenerator} class is used to generate X.509
 *   certificates. To create an instance of this class, one must provide a
 *   certificate authority certificate and key pair. To create a certificate, it
 *   is necessary to provide a newly generated key pair and certificate
 *   information under a {@link CertificateInfo} object.
 * </p>
 * <p></p>
 * <p>
 *   Create a certificate generator instance:
 *   <code>
 *     <p>var keyPairCA = new KeyPair(publicKeyCA, privateKeyCA);</p>
 *     <p>var generator = new CertificateGenerator(certAuthority, keyPairCA);</p>
 *   </code>
 * </p>
 * <p>
 *   Generate a new certificate:
 *   <code>
 *     <p>var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC);</p>
 * 		 <p>keyPairGenerator.initialize(2048);</p>
 * 		 <p>var keyPair =  keyPairGenerator.generateKeyPair();</p>
 *     <p>var x509certificate = generator.createCertificate(info, keyPair);</p>
 *   </code></p>
 * </p>
 **/
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

	/**
	 * Generate a certificate by creating a CSR (Certificate Signing Request) with
	 * the license information and the public key provided. The CSR is then signed
	 * by the certificate authority.
	 */
	public X509Certificate createCertificate(CertificateInfo info, KeyPair keyPair) {
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
						 NoSuchProviderException | SignatureException |
						 CertificateException e) {
			throw new RuntimeException("Error while creating the license "
					+ "certificate.", e);
		}
	}

	/**
	 * Adding extensions to the CSR:
	 *  - type of certificate,
	 *  - certificate authority information,
	 *  - certificate usage.
	 */
	private void addExtensions(X509v3CertificateBuilder certBuilder,
			PKCS10CertificationRequest csr) {
		try {
			var extensionUtils = new JcaX509ExtensionUtils();

			// Use BasicConstraints to say that this certificate is not a CA
			certBuilder.addExtension(Extension.basicConstraints, true,
					new BasicConstraints(false));

			// Add issuer key identifier as an Extension
			var certCA = new JcaX509CertificateConverter().getCertificate(certAuth);
			var authId = extensionUtils.createAuthorityKeyIdentifier(certCA);
			var keyIdCA = Extension.authorityKeyIdentifier;
			certBuilder.addExtension(keyIdCA, false, authId);

			// Add subject key identifier as an Extension
			var subjectId = extensionUtils.createSubjectKeyIdentifier(
					csr.getSubjectPublicKeyInfo());
			var keyIdSubject = Extension.subjectKeyIdentifier;
			certBuilder.addExtension(keyIdSubject, false, subjectId);

			// Add intended key usage Extension
			var keyUsage = new KeyUsage(KeyUsage.digitalSignature);
			certBuilder.addExtension(Extension.keyUsage, false, keyUsage);
		} catch (NoSuchAlgorithmException | CertIOException | CertificateException e) {
			throw new RuntimeException("Error while adding the extensions to the "
					+ "license certificate.", e);
		}
	}

	/**
	 * Lazily creates a CSR content signer built with the certificate authority
	 * private key.
	 */
	private ContentSigner getCsrContentSigner() {
		if (csrContentSigner == null) {
			var csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
			csrBuilder.setProvider(BC);

			// Sign the new KeyPair with the CA private key
			try {
				csrContentSigner = csrBuilder.build(keyPairCA.getPrivate());
			} catch (OperatorCreationException e) {
				throw new RuntimeException("Error while creating the CST content "
						+ "signer.", e);
			}
		}
		return csrContentSigner;
	}

	private X509v3CertificateBuilder getCertBuilder(CertificateInfo info,
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

	private PKCS10CertificationRequest createCSR(CertificateInfo info, PublicKey
			publicKey) {
		var subject = info.subject().asX500Name();
		if (subject.getRDNs().length == 0) {
			throw new RuntimeException("Error while processing the X500 name of the "
					+ "license subject: " + info.subject().asRDNString());
		}

		var builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
		var csrContentSigner = getCsrContentSigner();
		return builder.build(csrContentSigner);
	}

	/**
	 * Convert the certificate to Base64, the industry standard for SSL
	 * certificate content.
	 */
	public static String toBase64(X509Certificate certificate)
			throws CertificateEncodingException {
		var bytes = certificate.getEncoded();
		return BEGIN + new String(Base64.encode(bytes)) + END;
	}

}
