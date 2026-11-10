package org.openlca.license.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.stream.Stream;

/// The Person records data specific to the X.500 directory service.
///
/// For example the following string representation of an X.500 entry:
///
/// ```
/// UID=lee.rosanna,CN=Rosanna Lee,C=US,E=lee.rosanna@sun.org,O=Sun
/// ```
///
/// can be created with:
///
/// ```
/// var person = new Person(
///     "lee.rosanna", "Rosanna Lee", "US", "lee.rosanna@sun.org", "Sun");
/// ```
///
/// Fields that are `null` or empty are not added to the X.500 name. When
/// reading a name, missing fields are returned as empty strings.
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

	/// @param name a string representation of the X.500 distinguished name
	///             using the format defined in RFC 2253.
	public static Person of(String name) {
		return Person.of(new X500Name(name));
	}

	public static String get(X500Name name, ASN1ObjectIdentifier identifier) {
		var rdn = name.getRDNs(identifier);
		if (rdn.length > 0) {
			return rdn[0].getFirst().getValue().toString();
		} else
			return "";
	}

	public X500Name asX500Name() {
		var builder = new X500NameBuilder(BCStyle.INSTANCE);
		add(builder, BCStyle.UID, userName);
		add(builder, BCStyle.CN, commonName);
		add(builder, BCStyle.C, country);
		add(builder, BCStyle.E, email);
		add(builder, BCStyle.O, organisation);
		return builder.build();
	}

	/// Adds the value to the builder if it is not `null` or empty. The
	/// [X500NameBuilder] fails with a `NullPointerException` for `null` values
	/// and empty values are not allowed for most attributes (RFC 5280).
	private static void add(
			X500NameBuilder builder, ASN1ObjectIdentifier oid, String value) {
		if (value == null || value.isEmpty())
			return;
		builder.addRDN(oid, value);
	}

	public String asRDNString() {
		return asX500Name().toString();
	}

}
