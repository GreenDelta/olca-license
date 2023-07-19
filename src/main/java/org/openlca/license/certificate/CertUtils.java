package org.openlca.license.certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertUtils {

	/**
	 * Retrieve the public key from a certificate.
	 * The certificate should be encoded in standard Base64.
	 */
	public static PublicKey getPublicKey(InputStream inputStream) {
		try {
			X509Certificate cert = getX509Certificate(inputStream);
			JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			return converter.getPublicKey(holder.getSubjectPublicKeyInfo());
		} catch (CertificateException | PEMException e) {
			throw new RuntimeException("Error while getting the public key.", e);
		}
	}

	public static X509Certificate getX509Certificate(InputStream inputStream) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(inputStream);
		} catch (CertificateException e) {
			throw new RuntimeException("Error while generating an X509 certificate "
					+ "from an InputStream.", e);
		}
	}

}
