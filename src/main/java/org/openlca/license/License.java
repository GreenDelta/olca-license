package org.openlca.license;

import static org.openlca.license.Licensor.INDICES;
import static org.openlca.license.Licensor.JSON;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Base64;
import org.openlca.license.access.Credentials;
import org.openlca.license.access.LicenseStatus;
import org.openlca.license.access.Session;
import org.openlca.license.certificate.CertUtils;
import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.certificate.CertificateVerifier;
import org.openlca.license.signature.SignatureVerifier;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;

/**
 * <p>
 * {@link License} is a record used to gather the information that certified a
 * data library.
 * </p>
 *
 * @param certificate
 *            X.509 certificate of the data library encoded in Base64.
 * @param signatures
 *            Mapping of the file names to their digital signature encoded in
 *            Base64.
 * @param authority
 *            X.509 certificate of the certificate authority that delivered the
 *            data library certificate.
 */
public class License {

	private final String certificate;
	private final Map<String, String> signatures;
	private final String authority;

	public License(String certificate, Map<String, String> signatures, String authority) {
		this.certificate = certificate;
		this.signatures = signatures;
		this.authority = authority;
	}

	public String certificate() {
		return certificate;
	}

	public Map<String, String> signatures() {
		return signatures;
	}

	public String authority() {
		return authority;
	}

	public static Optional<License> of(File library) {
		File json = new File(library, JSON);
		if (!json.exists())
			return Optional.empty();

		try {
			JsonReader reader = new JsonReader(new FileReader(json));
			Gson gson = new Gson();
			Type mapType = new TypeToken<License>() {
			}.getType();
			return Optional.of(gson.fromJson(reader, mapType));
		} catch (FileNotFoundException e) {
			throw new RuntimeException("Error while reading the license file.", e);
		}
	}

	public Map<String, byte[]> signaturesAsBytes() {
		HashMap<String, byte[]> bytes = new HashMap<String, byte[]>();
		signatures.forEach((key, value) -> bytes.put(key, Base64.decode(value)));
		return bytes;
	}

	public CertificateInfo getInfo() {
		byte[] certBytes = certificate().getBytes();
		return CertificateInfo.of(new ByteArrayInputStream(certBytes));
	}

	public PublicKey getCertPublicKey() {
		ByteArrayInputStream bis = new ByteArrayInputStream(certificate().getBytes());
		return CertUtils.getPublicKey(bis);
	}

	public X509Certificate getCertAsX509() {
		ByteArrayInputStream bis = new ByteArrayInputStream(certificate().getBytes());
		return CertUtils.getX509Certificate(bis);
	}

	public X509Certificate getCAAsX509() {
		ByteArrayInputStream bis = new ByteArrayInputStream(authority().getBytes());
		return CertUtils.getX509Certificate(bis);
	}

	/**
	 * Check the status of the {@link License} by checking the {@link Session}.
	 *
	 * @see License#status(File, Cipher, String)
	 */
	public LicenseStatus status(File library, Session session) throws IOException {
		Cipher cipher = getDecryptCipher(session);
		return status(library, cipher, session.user());
	}

	/**
	 * Check the status of the {@link License} by checking the
	 * {@link Credentials}.
	 *
	 * @see License#status(File, Cipher, String)
	 */
	public LicenseStatus status(File library, Credentials credentials) throws IOException {
		Cipher cipher = getDecryptCipher(credentials);
		return status(library, cipher, credentials.user());
	}

	/**
	 * <p>
	 * Check the status of a {@link License} by sequentially testing:
	 * </p>
	 * <ol>
	 * <li>the authenticity of the certificate,</li>
	 * <li>the start and expiry date of the license,</li>
	 * <li>the signatures of the library files,</li>
	 * <li>the email address of the user,</li>
	 * <li>the password of the user.</li>
	 * </ol>
	 *
	 * @param library
	 *            the folder of the library
	 * @param cipher
	 *            a decryption cipher to test the password
	 * @param user
	 *            the email of the user
	 */
	public LicenseStatus status(File library, Cipher cipher, String user) throws IOException {
		CertificateInfo info = getInfo();

		if (!info.isValid()) {
			Date date = new Date();
			if (info.notBefore().after(date))
				return LicenseStatus.NOT_YET_VALID;
			if (info.notAfter().before(date))
				return LicenseStatus.EXPIRED;
		}

		if (!CertificateVerifier.verify(getCertAsX509(), getCAAsX509()))
			return LicenseStatus.UNTRUSTED;

		SignatureVerifier signAgent = new SignatureVerifier(getCertPublicKey(), signaturesAsBytes());

		ArrayList<Path> blacklist = new ArrayList<Path>();
		blacklist.add(new File(library, JSON).toPath());
		if (!signAgent.verify(library, blacklist))
			return LicenseStatus.CORRUPTED;

		if (!user.equals(info.subject().email()))
			return LicenseStatus.WRONG_USER;

		if (!checkEncryption(library, cipher)) {
			return LicenseStatus.WRONG_PASSWORD;
		}

		return LicenseStatus.VALID;
	}

	/**
	 *
	 * @param library
	 *            the library folder
	 * @param cipher
	 *            a decryption cipher.
	 */
	private boolean checkEncryption(File library, Cipher cipher) throws IOException {
		String encrypted;
		try (Stream<Path> walk = Files.walk(library.toPath())) {
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

		File output = File.createTempFile("out", null);
		try (FileInputStream in = new FileInputStream(new File(library, encrypted + ".enc"));
				FileOutputStream out = new FileOutputStream(output)) {
			try {
				Crypto.doCrypto(cipher, in, out);
			} catch (BadPaddingException e) {
				return false;
			}
		}
		return true;
	}

	public Session createSession(Credentials credentials) {
		if (!credentials.user().equals(getInfo().subject().email()))
			return null;
		char[] password = credentials.password();
		byte[] salt = getCertPublicKey().getEncoded();
		byte[] secret = Crypto.getSecret(password, salt);
		String encoded = new String(Base64.encode(secret));
		return new Session(getInfo().subject().email(), encoded);
	}

	public Cipher getDecryptCipher(Credentials credentials) {
		char[] password = credentials.password();
		byte[] salt = getCertPublicKey().getEncoded();
		return Crypto.getCipher(Cipher.DECRYPT_MODE, password, salt);
	}

	public Cipher getDecryptCipher(Session session) {
		if (!session.user().equals(getInfo().subject().email()))
			return null;
		byte[] decoded = Base64.decode(session.secret());
		return Crypto.getCipher(Cipher.DECRYPT_MODE, decoded);
	}

	@Override
	public int hashCode() {
		return Objects.hash(certificate, signatures, authority);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof License))
			return false;
		License other = (License) obj;
		return Objects.equals(certificate, other.certificate)
				&& Objects.equals(signatures, other.signatures)
				&& Objects.equals(authority, other.authority);
	}
}
