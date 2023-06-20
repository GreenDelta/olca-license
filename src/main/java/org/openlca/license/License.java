package org.openlca.license;

import org.bouncycastle.util.encoders.Base64;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *   License is a record used to gather the information that certified a data
 *   library.
 * </p>
 *
 * @param certificate X.509 certificate of the data library encoded in Base64.
 * @param signatures Mapping of the file names to their digital signature
 *                   encoded in Base64.
 * @param authority X.509 certificate of the certificate authority that
 *                  delivered the data library certificate.
 */
public record License(
		String certificate,
		Map<String, String> signatures,
		String authority
) {

	public Map<String, byte[]> signaturesAsBytes() {
		var bytes = new HashMap<String, byte[]>();
		signatures.forEach((key, value) -> bytes.put(key, Base64.decode(value)));
		return bytes;
	}

}
