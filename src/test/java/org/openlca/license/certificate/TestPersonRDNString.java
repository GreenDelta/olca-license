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

}
