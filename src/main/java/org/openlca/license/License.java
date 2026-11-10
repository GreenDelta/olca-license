package org.openlca.license;

import com.google.gson.Gson;
import org.bouncycastle.util.encoders.Base64;
import org.openlca.license.access.Credentials;
import org.openlca.license.access.LicenseStatus;
import org.openlca.license.access.Session;
import org.openlca.license.certificate.CertUtils;
import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.certificate.CertificateVerifier;
import org.openlca.license.signature.SignatureVerifier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.openlca.license.Licensor.INDICES;
import static org.openlca.license.Licensor.JSON;

/// [License] is a record used to gather the information that certified a
/// data library.
///
/// @param certificate X.509 certificate of the data library encoded in Base64.
/// @param signatures  Mapping of the file names to their digital signature
///                    encoded in Base64.
/// @param authority   X.509 certificate of the certificate authority that
///                    delivered the data library certificate.
public record License(String certificate, Map<String, String> signatures,
		String authority) {

	public static Optional<License> of(File library) {
		var json = new File(library, JSON);
		if (!json.exists())
			return Optional.empty();

		// the reader must be closed, otherwise the file could stay locked (on
		// Windows) and the library folder could not be deleted
		try (var reader = Files.newBufferedReader(
				json.toPath(), StandardCharsets.UTF_8)) {
			return Optional.of(new Gson().fromJson(reader, License.class));
		} catch (IOException e) {
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

	public PublicKey getCertPublicKey() {
		var bis = new ByteArrayInputStream(certificate().getBytes());
		return CertUtils.getPublicKey(bis);
	}

	public X509Certificate getCertAsX509() {
		var bis = new ByteArrayInputStream(certificate().getBytes());
		return CertUtils.getX509Certificate(bis);
	}

	public X509Certificate getCAAsX509() {
		var bis = new ByteArrayInputStream(authority().getBytes());
		return CertUtils.getX509Certificate(bis);
	}

	/// Check the status of the [License] by checking the [Session].
	///
	/// @see #status(File, Cipher, String)
	public LicenseStatus status(File library, Session session) throws
			IOException {
		var cipher = getDecryptCipher(session);
		return status(library, cipher, session.user());
	}

	/// Check the status of the [License] by checking the [Credentials].
	///
	/// @see #status(File, Cipher, String)
	public LicenseStatus status(File library, Credentials credentials) throws
			IOException {
		var cipher = getDecryptCipher(credentials);
		return status(library, cipher, credentials.user());
	}

	/// Check the status of a [License] by sequentially testing:
	///
	/// 1. the authenticity of the certificate,
	/// 2. the start and expiry date of the license,
	/// 3. the signatures of the library files,
	/// 4. the username or email address of the user,
	/// 5. the password of the user.
	///
	/// @param library the folder of the library
	/// @param cipher  a decryption cipher to test the password
	/// @param user    the username or email address of the user
	public LicenseStatus status(File library, Cipher cipher, String user) throws
			IOException {
		var info = getInfo();

		if (!info.isValid()) {
			var date = new Date();
			if (info.notBefore().after(date))
				return LicenseStatus.NOT_YET_VALID;
			if (info.notAfter().before(date))
				return LicenseStatus.EXPIRED;
		}

		if (!CertificateVerifier.verify(getCertAsX509(), getCAAsX509()))
			return LicenseStatus.UNTRUSTED;

		var signAgent = new SignatureVerifier(getCertPublicKey(), signaturesAsBytes());

		var blacklist = new ArrayList<Path>();
		blacklist.add(new File(library, JSON).toPath());
		if (!signAgent.verify(library, blacklist))
			return LicenseStatus.CORRUPTED;

		if (!checkSubject(user))
			return LicenseStatus.WRONG_USER;

		if (!checkEncryption(library, cipher)) {
			return LicenseStatus.WRONG_PASSWORD;
		}

		return LicenseStatus.VALID;
	}

	/// Returns `true` if the given user matches the username or the email
	/// address of the certificate subject. Note that the username and email
	/// address can be the same, so we cannot put them into a `Set.of(..)`.
	private boolean checkSubject(String user) {
		if (user == null || user.isBlank())
			return false;
		var subject = getInfo().subject();
		return user.equals(subject.userName()) || user.equals(subject.email());
	}

	/// Tests if the given cipher can decrypt an encrypted index of the library.
	/// The decrypted data are discarded, so that they are never written to
	/// disk.
	///
	/// @param library the library folder
	/// @param cipher  a decryption cipher.
	private boolean checkEncryption(File library, Cipher cipher) throws
			IOException {
		Path encrypted;
		try (var walk = Files.walk(library.toPath())) {
			encrypted = walk
					.filter(Files::isRegularFile)
					.filter(path -> {
						var name = path.getFileName().toString();
						if (!name.endsWith(".enc"))
							return false;
						var baseName = name.substring(0, name.length() - 4);
						return INDICES.contains(baseName);
					})
					.findFirst()
					.orElse(null);
		}

		if (encrypted == null)
			return true;

		try (var in = Files.newInputStream(encrypted)) {
			Crypto.doCrypto(cipher, in, OutputStream.nullOutputStream());
			return true;
		} catch (BadPaddingException e) {
			return false;
		}
	}

	public Session createSession(Credentials credentials) {
		if (!checkSubject(credentials.user()))
			return null;
		var password = credentials.password();
		var salt = getCertPublicKey().getEncoded();
		var secret = Crypto.getSecret(password, salt);
		var encoded = new String(Base64.encode(secret));
		return new Session(credentials.user(), encoded);
	}

	public Cipher getDecryptCipher(Credentials credentials) {
		var password = credentials.password();
		var salt = getCertPublicKey().getEncoded();
		return Crypto.getCipher(Cipher.DECRYPT_MODE, password, salt);
	}

	public Cipher getDecryptCipher(Session session) {
		if (!checkSubject(session.user()))
			return null;
		var decoded = Base64.decode(session.secret());
		return Crypto.getCipher(Cipher.DECRYPT_MODE, decoded);
	}

}
