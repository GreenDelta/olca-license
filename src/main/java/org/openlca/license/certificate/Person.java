package org.openlca.license.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

import java.util.stream.Stream;

/**
 * <p>
 * The Person records data specific to the X.500 directory service.
 * </p>
 *
 * For example the following string representation of an X.500 entry:
 * <p><code>uid=lee.rosanna, cn=Rosanna Lee, e=lee.rosanna@sun.org, o=Sun,
 * c=us</code>
 * <code></p>
 * can be created with:
 * <p><code>
 *   var person = new Person("lee.rosanna", "Rosanna Lee", "US,
 *   "lee.rosanna@sun.org", "Sun);
 * </code></p>
 */
public record Person(
		String userName,
		String commonName,
		String country,
		String email,
		String organisation
) {

	public Person {
		if (Stream.of(userName, email).noneMatch(s -> s != null && !s.isBlank())) {
			throw new IllegalArgumentException("userName and email cannot be both "
					+ "null or blank.");
		}
	}

	public static Person of(X500Name name) {
		return new Person(
				get(name, BCStyle.UID),
				get(name, BCStyle.CN),
				get(name, BCStyle.C),
				get(name, BCStyle.E),
				get(name, BCStyle.O)
		);
	}

	/**
	 * @param name a string representation of the X.500 distinguished name using
	 *             the format defined in RFC 2253.
	 */
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

	public String asRDNString() {
		return String.format("UID=%s,CN=%s,C=%s,E=%s,O=%s",
				userName, commonName, country, email, organisation);
	}

	public X500Name asX500Name() {
		return new X500Name(asRDNString());
	}

}
