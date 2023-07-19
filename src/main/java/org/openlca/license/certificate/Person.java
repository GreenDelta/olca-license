package org.openlca.license.certificate;

import java.util.Objects;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;

/**
 * <p>
 * The Person records data specific to the X.500 directory service.
 * </p>
 *
 * For example the following string representation of an X.500 entry:
 * <p>
 * <code>cn=Rosanna Lee, e=lee.rosanna@sun.org, o=Sun, c=us</code> <code></p>
 * can be created with:
 * <p><code>
 *   var person = new Person("Rosanna Lee", "US, "lee.rosanna@sun.org", "Sun);
 * </code>
 * </p>
 */
public class Person {

	private final String commonName;
	private final String country;
	private final String email;
	private final String organisation;

	public Person(String commonName, String country, String email, String organisation) {
		this.commonName = commonName;
		this.country = country;
		this.email = email;
		this.organisation = organisation;
	}

	public String commonName() {
		return commonName;
	}

	public String country() {
		return country;
	}

	public String email() {
		return email;
	}

	public String organisation() {
		return organisation;
	}

	public static Person of(X500Name name) {
		return new Person(
				get(name, BCStyle.CN),
				get(name, BCStyle.C),
				get(name, BCStyle.E),
				get(name, BCStyle.O));
	}

	public static Person of(String name) {
		return Person.of(new X500Name(name));
	}

	public static String get(X500Name name, ASN1ObjectIdentifier identifier) {
		RDN[] rdn = name.getRDNs(identifier);
		if (rdn.length > 0) {
			return IETFUtils.valueToString(rdn[0].getFirst().getValue());
		} else
			return "";
	}

	public String asRDNString() {
		return String.format("CN=%s,C=%s,E=%s,O=%s", commonName, country, email,
				organisation);
	}

	public X500Name asX500Name() {
		return new X500Name(asRDNString());
	}

	@Override
	public int hashCode() {
		return Objects.hash(commonName, country, email, organisation);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof Person))
			return false;
		Person other = (Person) obj;
		return Objects.equals(commonName, other.commonName)
				&& Objects.equals(country, other.country)
				&& Objects.equals(email, other.email)
				&& Objects.equals(organisation, other.organisation);
	}

}
