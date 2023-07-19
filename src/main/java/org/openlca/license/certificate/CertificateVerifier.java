package org.openlca.license.certificate;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;

/**
 * The {@link CertificateVerifier} class is used to verify a certificate against
 * a certificate authority.
 */
public class CertificateVerifier {

	/**
	 * Verify an X.509 certificate against a certificate authority.
	 *
	 * @param cert the certificate to be verified.
	 * @param auth the certificate authority.
	 */
	public static boolean verify(X509Certificate cert, X509Certificate auth) {
		CertPath certPath = getCertPath(cert);
		Set<TrustAnchor> trustAnchors = getTrustAnchors(auth);

		try {
			PKIXParameters parameters = new PKIXParameters(trustAnchors);
			parameters.setRevocationEnabled(false);

			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			validator.validate(certPath, parameters);
			return true;
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new RuntimeException("Error while verifying the certificate with "
					+ "the certificate authority.", e);
		} catch (CertPathValidatorException e) {
			return false;
		}
	}

	private static Set<TrustAnchor> getTrustAnchors(X509Certificate authority) {
		TrustAnchor anchor = new TrustAnchor(authority, null);
		return Collections.singleton(anchor);
	}

	private static CertPath getCertPath(X509Certificate cert) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
			certificates.add(cert);
			return cf.generateCertPath(certificates);
		} catch (CertificateException e) {
			throw new RuntimeException("Error while generating the certificate path "
					+ "from X509 certificate.", e);
		}
	}

}
