package org.openlca.license.certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
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
			var cert = getX509Certificate(inputStream);
			var holder = new JcaX509CertificateHolder(cert);
			var converter = new JcaPEMKeyConverter();
			return converter.getPublicKey(holder.getSubjectPublicKeyInfo());
		} catch (CertificateException | PEMException e) {
			throw new RuntimeException("Error while getting the public key.", e);
		}
	}

	public static X509Certificate getX509Certificate(InputStream inputStream) {
		try {
			var cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(inputStream);
		} catch (CertificateException e) {
			throw new RuntimeException("Error while generating an X509 certificate "
					+ "from an InputStream.", e);
		}
	}

	/**
	 * Returns the {@link PublicKey} of a certificate.
	 */
	public static PublicKey getPublicKeyCA(X509CertificateHolder cert)
			throws PEMException {
		var publicKeyInfo = cert.getSubjectPublicKeyInfo();
		var converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(publicKeyInfo);
	}

	/**
	 * Returns the {@link PrivateKey} from a certificate authority folder
	 * structured in respect with the industry standard:
	 * </p>
	 * <p>
	 * The industrial standard for a CA file structure is as follow:
	 *   <ul>
	 *     <li>
	 *       private
	 *       <ul>
	 *         <li>[folder libName].key</li>
	 *       </ul>
	 *     </li>
	 *     <li>[folder libName].crt</li>
	 *   </ul>
	 * </p>
	 */
	public static PrivateKey getPrivateKeyCA(File ca)
			 throws IOException {
		var privateDir = new File(ca, "private");
		var keyName = ca.getName() + ".key";
		var keyInfo = getPrivateKeyInfo(new File(privateDir, keyName));
		if (keyInfo == null)
			return null;
		var converter = new JcaPEMKeyConverter();
		return converter.getPrivateKey(keyInfo);
	}

	public static X509CertificateHolder getX509CertificateHolder(File file)
			throws IOException {
		var object = getPEMObject(file);
		return object instanceof X509CertificateHolder holder
				? holder
				: null;
	}

	public static PrivateKeyInfo getPrivateKeyInfo(File file) throws IOException {
		var object = getPEMObject(file);
		return object instanceof PrivateKeyInfo info
				? info
				: null;
	}

	private static Object getPEMObject(File file)  throws  IOException {
		try (var stream = new FileInputStream(file);
				 var reader = new InputStreamReader(stream);
				 var parser = new PEMParser(reader)) {
			return parser.readObject();
		}
	}

}
