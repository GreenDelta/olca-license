package org.openlca.license.certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertUtils {

	public static PublicKey getPublicKey(InputStream inputStream)
			throws IOException {
		try {
			var cf = CertificateFactory.getInstance("X.509");

			var cert = (X509Certificate) cf.generateCertificate(inputStream);
			var holder = new JcaX509CertificateHolder(cert);
			var converter = new JcaPEMKeyConverter();
			return converter.getPublicKey(holder.getSubjectPublicKeyInfo());
		} catch (CertificateException e) {
			throw new RuntimeException("Error while getting the public key.", e);
		}
	}

}
