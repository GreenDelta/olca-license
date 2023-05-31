package org.openlca.license;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;


public class License {

	public final Date notBefore;
	public final Date notAfter;
	public final boolean[] keyUsage;
	public final PublicKey publicKey;
	public final Person subject;
	public final Person issuer;

	private License(X509Certificate cert, JcaX509CertificateHolder holder) {
		notBefore = holder.getNotBefore();
		notAfter = holder.getNotAfter();
		subject = Person.of(holder.getSubject());
		issuer = Person.of(holder.getIssuer());
		keyUsage = cert.getKeyUsage();
		publicKey = cert.getPublicKey();
	}

	public static License of(File file) throws FileNotFoundException,
			CertificateException {
		var inStream = new FileInputStream(file);
		var cf = CertificateFactory.getInstance("X.509");
		var cert = (X509Certificate) cf.generateCertificate(inStream);
		var certHolder = new JcaX509CertificateHolder(cert);
		return new License(cert, certHolder);
	}

	public boolean isValid() {
		var date = new Date();
		return notBefore.before(date) && notAfter.after(date);
	}

	public record Person(String commonName, String country, String email,
											 String organisation) {

		public static Person of(X500Name name) {
			return new Person(
					get(name, BCStyle.CN),
					get(name, BCStyle.C),
					get(name, BCStyle.E),
					get(name, BCStyle.O)
			);
		}

		public static String get(X500Name name, ASN1ObjectIdentifier identifier) {
			var rdn = name.getRDNs(identifier);
			if (rdn.length > 0) {
				return IETFUtils.valueToString(rdn[0].getFirst().getValue());
			} else
				return "";
		}

	}

}
