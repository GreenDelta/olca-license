package org.openlca.license;

import org.openlca.license.certificate.LicenseInfo;
import org.openlca.license.certificate.Person;

import java.util.Calendar;

public class TestUtils {

	public static LicenseInfo getTestLicenseInfo() {
		var calendar = Calendar.getInstance();
		calendar.set(2021, Calendar.JULY, 20, 21, 37, 0);
		var startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		var endDate = calendar.getTime();

		var subject = new Person("John Doe", "US",
				"john@green-company.com", "Green Company");
		var caPerson = new Person("Nexus CA", "DE", "", "Green Delta");

		return new LicenseInfo(startDate, endDate, subject, caPerson);
	}

}
