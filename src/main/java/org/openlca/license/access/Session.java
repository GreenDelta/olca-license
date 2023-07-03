package org.openlca.license.access;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

public record Session(String user, String secret) {

	public String toJson() {
		var gson = new GsonBuilder().setPrettyPrinting().create();
		return gson.toJson(this);
	}

	public static Session fromJson(JsonReader json) {
		var gson = new Gson();
		var mapType = new TypeToken<Session>() {}.getType();
		return gson.fromJson(json, mapType);
	}

}
