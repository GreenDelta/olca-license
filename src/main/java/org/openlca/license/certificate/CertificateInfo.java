package org.openlca.license.certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * The {@link CertificateInfo} records data necessary to the creation or reading
 * of a certificate.
 * @param notBefore Date before which the certificate is not valid (to the
 *                 second).
 * @param notAfter Date after which the certificate is not valid (to the
 *  *                 second).
 * @param subject Owner of the certificate.
 * @param issuer Authority that is signing the CSR to create the certificate.
 */
public record CertificateInfo(Date notBefore, Date notAfter, Person subject,
															Person issuer) {

	public static CertificateInfo of(InputStream inputStream) {
		try {
			var cf = CertificateFactory.getInstance("X.509");

			var cert = (X509Certificate) cf.generateCertificate(inputStream);
			var holder = new JcaX509CertificateHolder(cert);

			return new CertificateInfo(
					holder.getNotBefore(),
					holder.getNotAfter(),
					Person.of(holder.getSubject()),
					Person.of(holder.getIssuer())
			);
		} catch (CertificateException e) {
			throw new RuntimeException("Error while parsing the X.509 certificate "
					+ "into a " + CertificateInfo.class + "object.", e);
		}
	}

	public boolean isValid() {
		var date = new Date();
		return notBefore.before(date) && notAfter.after(date);
	}

	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof CertificateInfo other))
			return false;
		var notBeforeEqual = areDateEqual(other.notBefore(), notBefore);
		var notAfterEqual = areDateEqual(other.notAfter(), notAfter);
		var subjectEqual = subject.equals(other.subject());
		var issuerEqual = issuer.equals(other.issuer());

		return notBeforeEqual && notAfterEqual && subjectEqual && issuerEqual;
	}

	/**
	 * Check if the provided dates are equal to the second. This is necessary as
	 * the certificate builder might round up the date to the second.
	 */
	private boolean areDateEqual(Date date1, Date date2) {
		var diff = Math.abs(date1.getTime() - date2.getTime());
		return diff < 1000;
	}

}
