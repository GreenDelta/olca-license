package org.openlca.license.certificate;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestPersonRDNString {

	@Test
	public void testEscapeComma() {
		var person = new Person(
				"jdoe",
				"John Doe",
				"US",
				"john@example.com",
				"Company, Inc.");
		var rdn = person.asRDNString();
		var parsed = Person.of(rdn);
		assertEquals(person.organisation(), parsed.organisation());
	}

	@Test
	public void testEscapePlus() {
		var person = new Person(
				"jdoe",
				"John Doe",
				"US",
				"john+tag@example.com",
				"Company");
		var rdn = person.asRDNString();
		var parsed = Person.of(rdn);
		assertEquals(person.email(), parsed.email());
	}

	/// Fields that are `null` or empty are not added to the X.500 name, and
	/// missing fields are read as empty strings. Before, a `null` field
	/// resulted in a `NullPointerException` in the `X500NameBuilder`.
	@Test
	public void testNullAndEmptyFields() {
		var person = new Person("jdoe", null, "", "john@example.com", null);
		var name = person.asX500Name();
		assertEquals(2, name.getRDNs().length);
		assertEquals("UID=jdoe,E=john@example.com", person.asRDNString());

		var parsed = Person.of(name);
		assertEquals("jdoe", parsed.userName());
		assertEquals("", parsed.commonName());
		assertEquals("", parsed.country());
		assertEquals("john@example.com", parsed.email());
		assertEquals("", parsed.organisation());
	}

}
