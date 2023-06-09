package org.openlca.license;

public class LicenseException extends Exception {

	public LicenseException(String message, Throwable throwable) {
		super(message, throwable);
	}

	public LicenseException(String message) {
		super(message);
	}

}
