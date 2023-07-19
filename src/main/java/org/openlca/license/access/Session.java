package org.openlca.license.access;

import java.lang.reflect.Type;
import java.util.Objects;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

public class Session {

	private final String user;
	private final String secret;

	public Session(String user, String secret) {
		this.user = user;
		this.secret = secret;
	}

	public String user() {
		return user;
	}

	public String secret() {
		return secret;
	}

	public String toJson() {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		return gson.toJson(this);
	}

	public static Session fromJson(JsonReader json) {
		Gson gson = new Gson();
		Type mapType = new TypeToken<Session>() {
		}.getType();
		return gson.fromJson(json, mapType);
	}

	@Override
	public int hashCode() {
		return Objects.hash(user, secret);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof Session))
			return false;
		Session other = (Session) obj;
		return Objects.equals(user, other.user)
				&& Objects.equals(secret, other.secret);
	}

}
