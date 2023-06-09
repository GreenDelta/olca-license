package org.openlca.license.certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;


public record LicenseInfo(Date notBefore, Date notAfter, Person subject,
													Person issuer) {

	public static LicenseInfo of(File file) throws FileNotFoundException,
			CertificateException {
		var inStream = new FileInputStream(file);
		var cf = CertificateFactory.getInstance("X.509");
		var cert = (X509Certificate) cf.generateCertificate(inStream);
		var holder = new JcaX509CertificateHolder(cert);
		return new LicenseInfo(
				holder.getNotBefore(),
				holder.getNotAfter(),
				Person.of(holder.getSubject()),
				Person.of(holder.getIssuer())
		);
	}

	public boolean isValid() {
		var date = new Date();
		return notBefore.before(date) && notAfter.after(date);
	}

	@Override
	public boolean equals(Object o) {
		if (o == this)
			return true;
		if (!(o instanceof LicenseInfo other))
			return false;
		var notBeforeEqual = areDateEqual(other.notBefore(), notBefore);
		var notAfterEqual = areDateEqual(other.notAfter(), notAfter);
		var subjectEqual = subject.equals(other.subject());
		var issuerEqual = issuer.equals(other.issuer());

		return notBeforeEqual && notAfterEqual && subjectEqual && issuerEqual;
	}

	private boolean areDateEqual(Date date1, Date date2) {
		var diff = Math.abs(date1.getTime() - date2.getTime());
		return diff < 1000;
	}

}
