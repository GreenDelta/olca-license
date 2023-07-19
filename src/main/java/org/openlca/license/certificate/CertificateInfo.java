package org.openlca.license.certificate;

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * The {@link CertificateInfo} records data necessary to the creation or reading
 * of a certificate.
 * 
 * @param notBefore
 *            Date before which the certificate is not valid (to the second).
 * @param notAfter
 *            Date after which the certificate is not valid (to the * second).
 * @param subject
 *            Owner of the certificate.
 * @param issuer
 *            Authority that is signing the CSR to create the certificate.
 */
public class CertificateInfo {

	private final Date notBefore;
	private final Date notAfter;
	private final Person subject;
	private final Person issuer;

	public CertificateInfo(Date notBefore, Date notAfter, Person subject, Person issuer) {
		this.notBefore = notBefore;
		this.notAfter = notAfter;
		this.subject = subject;
		this.issuer = issuer;
	}

	public Date notBefore() {
		return notBefore;
	}
	
	public Date notAfter() {
		return notAfter;
	}
	
	public Person subject() {
		return subject;
	}

	public Person issuer() {
		return issuer;
	}

	
	public static CertificateInfo of(InputStream inputStream) {
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
			JcaX509CertificateHolder holder = new JcaX509CertificateHolder(cert);

			return new CertificateInfo(
					holder.getNotBefore(),
					holder.getNotAfter(),
					Person.of(holder.getSubject()),
					Person.of(holder.getIssuer()));
		} catch (CertificateException e) {
			throw new RuntimeException("Error while parsing the X.509 certificate "
					+ "into a " + CertificateInfo.class + "object.", e);
		}
	}

	public boolean isValid() {
		Date date = new Date();
		return notBefore.before(date) && notAfter.after(date);
	}

	@Override
	public int hashCode() {
		return Objects.hash(notBefore, notAfter, subject, issuer);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof CertificateInfo))
			return false;
		CertificateInfo other = (CertificateInfo) obj;
		return areDateEqual(notBefore, other.notBefore)
				&& areDateEqual(notAfter, other.notAfter)
				&& Objects.equals(subject, other.subject)
				&& Objects.equals(issuer, other.issuer);
	}

	/**
	 * Check if the provided dates are equal to the second. This is necessary as
	 * the certificate builder might round up the date to the second.
	 */
	private boolean areDateEqual(Date date1, Date date2) {
		long diff = Math.abs(date1.getTime() - date2.getTime());
		return diff < 1000;
	}

}
