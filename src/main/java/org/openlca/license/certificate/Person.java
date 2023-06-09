package org.openlca.license.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

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

	public static Person of(String name) {
		return Person.of(new X500Name(name));
	}

	public static String get(X500Name name, ASN1ObjectIdentifier identifier) {
		var rdn = name.getRDNs(identifier);
		if (rdn.length > 0) {
			return IETFUtils.valueToString(rdn[0].getFirst().getValue());
		} else
			return "";
	}

	private String asRDNString() {
		return String.format("CN=%s,C=%s,E=%s,O=%s", commonName, country, email,
				organisation);
	}

	public X500Name asX500Name() {
		return new X500Name(asRDNString());
	}

}
