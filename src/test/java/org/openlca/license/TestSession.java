package org.openlca.license;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openlca.license.access.Session;

import com.google.gson.stream.JsonReader;

public class TestSession {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Test
	public void testSession() throws IOException {
		Random rd = new Random();
		byte[] secret = new byte[128];
		rd.nextBytes(secret);
		String encoded = new String(Base64.encode(secret));
		Session expected = new Session("library", encoded);

		String json = expected.toJson();
		File file = tempFolder.newFile("json");

		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(json.getBytes());
		}

		JsonReader reader = new JsonReader(new FileReader(file));
		Session session = Session.fromJson(reader);
		assertEquals(expected.user(), session.user());
		assertEquals(expected.secret(), session.secret());
	}

}
