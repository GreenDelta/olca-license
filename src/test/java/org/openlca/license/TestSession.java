package org.openlca.license;

import com.google.gson.stream.JsonReader;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.access.Session;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Random;

import static org.junit.Assert.assertEquals;

public class TestSession {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Test
	public void testSession() throws IOException {
		var rd = new Random();
		var secret = new byte[128];
		rd.nextBytes(secret);
		var encoded = new String(Base64.encode(secret));
		var expected = new Session("library", encoded);

		var json = expected.toJson();
		var file = tempFolder.newFile("json");

		try (var fos = new FileOutputStream(file)) {
			fos.write(json.getBytes());
		}

		var reader = new JsonReader(new FileReader(file));
		var session = Session.fromJson(reader);
		assertEquals(expected.user(), session.user());
		assertEquals(expected.secret(), session.secret());
	}

}
