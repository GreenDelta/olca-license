package org.openlca.license;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import org.bouncycastle.util.encoders.Base64;
import org.openlca.license.certificate.CertUtils;
import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.signature.Verifier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.openlca.license.Licensor.INDICES;
import static org.openlca.license.Licensor.JSON;

/**
 * <p>
 * License is a record used to gather the information that certified a data
 * library.
 * </p>
 *
 * @param certificate X.509 certificate of the data library encoded in Base64.
 * @param signatures  Mapping of the file names to their digital signature
 *                    encoded in Base64.
 * @param authority   X.509 certificate of the certificate authority that
 *                    delivered the data library certificate.
 */
public record License(String certificate, Map<String, String> signatures,
											String authority) {

	public static License of(File library) {
		var json = new File(library, JSON);
		try {
			var reader = new JsonReader(new FileReader(json));
			var gson = new Gson();
			var mapType = new TypeToken<License>() {}.getType();
			return gson.fromJson(reader, mapType);
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Error while reading the license file.", e);
		}
	}

	public Map<String, byte[]> signaturesAsBytes() {
		var bytes = new HashMap<String, byte[]>();
		signatures.forEach((key, value) -> bytes.put(key, Base64.decode(value)));
		return bytes;
	}

	public CertificateInfo getInfo() {
		var certBytes = certificate().getBytes();
		return CertificateInfo.of(new ByteArrayInputStream(certBytes));
	}

	public PublicKey getCertificatePublicKey() {
		var bis = new ByteArrayInputStream(certificate().getBytes());
		return CertUtils.getPublicKey(bis);
	}

	public Verifier getSignatureVerifier() {
		return new Verifier(getCertificatePublicKey(), signaturesAsBytes());
	}

	public LicenseStatus status(File library, String email, char[] password)
			throws IOException {
		List<Path> blacklist = new ArrayList<>();
		blacklist.add(new File(library, JSON).toPath());
		return status(library, blacklist, email, password);
	}


	public LicenseStatus status(File library, List<Path> blacklist, String email,
			char[] password) throws IOException {
		var info = getInfo();

		if (!info.isValid()) {
			var date = new Date();
			if (info.notBefore().after(date))
				return LicenseStatus.NOT_YET_VALID;
			if (info.notAfter().before(date))
				return LicenseStatus.EXPIRED;
		}

		var signAgent = getSignatureVerifier();

		if (!signAgent.verify(library, blacklist))
			return LicenseStatus.CORRUPTED;

		if (!email.equals(info.subject().email()))
			return LicenseStatus.WRONG_USER;

		if (!checkEncryption(library, password)) {
			return LicenseStatus.WRONG_PASSWORD;
		}

		return LicenseStatus.VALID;
	}

	private boolean checkEncryption(File library, char[] password) throws
			IOException {
		String encrypted;
		try (var walk = Files.walk(library.toPath())) {
			encrypted = walk
					.map(Path::getFileName)
					.map(Path::toString)
					.map(n -> n.substring(0, n.length() - ".enc".length()))
					.filter(baseName -> INDICES.contains(baseName))
					.findFirst()
					.orElse(null);
		}

		if (encrypted == null)
			return true;

		var output = File.createTempFile("out", null);
		try (var in = new FileInputStream(new File(library, encrypted + ".enc"));
				 var out = new FileOutputStream(output)) {
			var salt = getCertificatePublicKey().getEncoded();
			try {
				Crypto.decrypt(password, salt, in, out);
			} catch (BadPaddingException e) {
				return false;
			}
		}

		return true;
	}

	public Cipher getDecryptCipher(char[] password) {
		var salt = getCertificatePublicKey().getEncoded();
		return Crypto.getCipher(Cipher.DECRYPT_MODE, password, salt);
	}

}
