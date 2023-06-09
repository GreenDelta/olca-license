package org.openlca.license;

import org.openlca.license.certificate.LicenseInfo;
import org.openlca.license.certificate.Person;

import java.util.Calendar;

public class TestUtils {

	public static LicenseInfo getTestLicenseInfo() {
		var calendar = Calendar.getInstance();
		calendar.add(Calendar.DATE, 1);
		var startDate = calendar.getTime();
		calendar.add(Calendar.YEAR, 1);
		var endDate = calendar.getTime();

		var subject = new Person("John Doe", "US",
				"john@green-company.com", "Green Company");
		var caPerson = new Person("Albert Dart", "DE",
				"albert@license.com", "Green Corp.");

		return new LicenseInfo(startDate, endDate, subject, caPerson);
	}

}
