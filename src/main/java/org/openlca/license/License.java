package org.openlca.license;

import org.bouncycastle.util.encoders.Base64;

import java.util.HashMap;
import java.util.Map;

public record License(String certificate,
											Map<String, String> signatures,
											String authority) {


	public Map<String, byte[]> signaturesAsBytes() {
		var bytes = new HashMap<String, byte[]>();
		signatures.forEach((key, value) -> bytes.put(key, Base64.decode(value)));
		return bytes;
	}
}
