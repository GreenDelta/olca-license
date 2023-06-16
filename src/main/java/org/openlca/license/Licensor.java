package org.openlca.license;

import com.google.gson.GsonBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;
import org.openlca.license.certificate.CertificateGenerator;
import org.openlca.license.certificate.LicenseInfo;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


/**
 * <p>
 * The Licensor class is used to generate the license elements of a
 * data library. A licensor is constructed by calling the static
 * method {@code getInstance} with a certificate authority as input.
 * </p>
 * <p>
 * The licensing of a data library consists in three operations:
 *   <ol>
 *     <li>creation of a X509 certificate signed by the issuer certificate
 *     authority with the information of the owner,</li>
 *     <li>symmetric encryption of the data indices with a key generated with
 *     the user password,</li>
 *     <li>signature of the data library with the above-mentioned certificate
 *     private key.</li>
 *   </ol>
 * </p>
 * <p>
 * In order to sign a data library, one can use the following lines:
 * <p>
 * <code>
 * var generator = LicenseGenerator.getInstance(CertAuthFileInputStream);
 * var licensedLib = generator.doLicensing(libraryFIS, licenseInfo, password);
 * </code>
 */
public class Licensor {

	private static final String BC = "BC";
	private static final String KEY_ALGORITHM = "RSA";
	public static final String JSON = "license.json";
	public static List<String> INDICES = List.of("index_A", "index_B", "index_C");

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public final X509CertificateHolder certAuthority;
	public final PrivateKey privateKeyCA;
	public final PublicKey publicKeyCA;

	private KeyPair keyPair;

	public Licensor(X509CertificateHolder ca, PublicKey publicKey,
			PrivateKey privateKey) {
		certAuthority = ca;
		publicKeyCA = publicKey;
		privateKeyCA = privateKey;
	}

	public static Licensor getInstance(File caDir)
			throws IOException {
		var parser = getPEMParser(new File(caDir, caDir.getName() + ".crt"));
		var certificate = (X509CertificateHolder) parser.readObject();

		var publicKey = getPublicKeyCA(certificate);
		var privateKey = getPrivateKeyCA(caDir);

		return new Licensor(certificate, publicKey, privateKey);
	}

	public void license(ZipInputStream input, ZipOutputStream output, String pass,
			LicenseInfo info) throws IOException {
		keyPair = generateKeyPair();
		var signer = new SignatureAgent.Signer(keyPair.getPrivate());

		var certificate = createCertificate(info);
		var authority = getAuthority();

		var zipEntry = input.getNextEntry();
		while (zipEntry != null) {
			if (INDICES.contains(zipEntry.getName() + ".bin")) {
				var index = new File(zipEntry.getName() + ".enc");
				try (var fos = new FileOutputStream(index)) {
					Crypto.encrypt(pass, keyPair.getPublic().getEncoded(), input, fos);
				}
				try (var fis = new FileInputStream(index)) {
					var indexEntry = new ZipEntry(index.getName());
					signer.write(fis, indexEntry, output);
				}
			} else {
				signer.write(input, zipEntry, output);
			}
			zipEntry = input.getNextEntry();
		}

		var signaturesAsBytes = signer.getSignatures();
		var signature = new HashMap<String, String>();
		signaturesAsBytes.forEach(
				(key, value) -> signature.put(key, new String(Base64.encode(value))));
		var license = new License(certificate, signature, authority);
		writeLicenseToJson(license, output);
	}

	private void writeLicenseToJson(License license, ZipOutputStream output)
			throws IOException {
		var gson = new GsonBuilder().setPrettyPrinting().create();
		var json = gson.toJson(license);
		var jsonInput = new ByteArrayInputStream(json.getBytes());
		var licenseEntry = new ZipEntry(JSON);
		output.putNextEntry(licenseEntry);
		var buffer = new byte[1024];
		int length;
		while((length = jsonInput.read(buffer)) >= 0) {
			output.write(buffer, 0, length);
		}
	}

	private String getAuthority() {
		try {
			var authority = new JcaX509CertificateConverter()
					.setProvider(BC)
					.getCertificate(certAuthority);
			return CertificateGenerator.toBase64(authority);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public String createCertificate(LicenseInfo info) {
		var keyPairCA = new KeyPair(publicKeyCA, privateKeyCA);
		var generator = new CertificateGenerator(certAuthority, keyPairCA);
		var x509certificate = generator.createCertificate(info, keyPair);

		try {
			return CertificateGenerator.toBase64(x509certificate);
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("Error while encoding the license certificate "
					+ "to Base64.", e);
		}
	}

	private static PublicKey getPublicKeyCA(X509CertificateHolder cert)
			throws PEMException {
		var publicKeyInfo = cert.getSubjectPublicKeyInfo();
		var converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(publicKeyInfo);
	}

	private static PrivateKey getPrivateKeyCA(File caDir)
			throws IOException {
		var privateDir = new File(caDir, "private");
		var keyName = caDir.getName() + ".key";
		var parser = getPEMParser(new File(privateDir, keyName));
		var password = getPassword(caDir);

		var converter = new JcaPEMKeyConverter();
		if (parser.readObject() instanceof PKCS8EncryptedPrivateKeyInfo keyInfo) {
			// Encrypted key - we will use provided password
			try {
				var decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
						.setProvider(BC)
						.build(password);
				var privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);
				return converter.getPrivateKey(privateKeyInfo);
			} catch (OperatorCreationException | PKCSException e) {
				throw new RuntimeException("Error while reading the private key of the "
						+ "certificate authority.", e);
			}
		}
		return null;
	}

	private static char[] getPassword(File caDir) throws IOException {
		var passFile = new File(caDir, caDir.getName() + ".pass");
		var buffer = new BufferedReader(new FileReader(passFile));
		var password = buffer.readLine();
		return password.toCharArray();
	}

	public static PEMParser getPEMParser(File file) throws FileNotFoundException {
		var stream = new FileInputStream(file);
		var reader = new InputStreamReader(stream);
		return new PEMParser(reader);
	}

	public static KeyPair generateKeyPair() {
		try {
			// Generate a new KeyPair and sign it using the CA private key by
			// generating a CSR (Certificate Signing Request)
			var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC);
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException("Error while generating the key pair of the "
					+ "license certificate.", e);
		}
	}

}
