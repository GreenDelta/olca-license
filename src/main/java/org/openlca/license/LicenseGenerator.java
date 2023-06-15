package org.openlca.license;

import com.google.gson.Gson;
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
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.List;


/**
 * <p>
 * The LicenseGenerator class is used to generate the license elements of a
 * data library. A license generator is constructed by calling the static
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
public class LicenseGenerator {

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

	public LicenseGenerator(X509CertificateHolder ca, PublicKey publicKey,
			PrivateKey privateKey) {
		certAuthority = ca;
		publicKeyCA = publicKey;
		privateKeyCA = privateKey;
	}

	public static LicenseGenerator getInstance(File caDir)
			throws IOException {
		var parser = getPEMParser(new File(caDir, caDir.getName() + ".crt"));
		var certificate = (X509CertificateHolder) parser.readObject();

		var publicKey = getPublicKeyCA(certificate);
		var privateKey = getPrivateKeyCA(caDir);

		return new LicenseGenerator(certificate, publicKey, privateKey);
	}

	public File doLicensing(File library, LicenseInfo info, String password)
			throws IOException {
		keyPair = generateKeyPair();

		var certificate = createCertificate(info);
		encryptIndices(library, password, keyPair.getPublic());
		var signature = getSignature(library);
		var authority = getAuthority();

		var license = new License(certificate, signature, authority);
		addLicenseToLibrary(license, library);

		return library;
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

	private String getSignature(File library) throws IOException {
		try {
			var signature = SignAgent.signFolder(library, keyPair.getPrivate());

			var publicKey = keyPair.getPublic();
			if (!SignAgent.verifySignature(library, signature, publicKey)) {
				throw new RuntimeException("The signature could not be verified.");
			}
			return new String(Base64.encode(signature));
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	private void addLicenseToLibrary(License license, File library)
			throws IOException {
		var gson = new Gson();
		var json = gson.toJson(license);
		var writer = new BufferedWriter(new FileWriter(new File(library, JSON)));
		writer.write(json);
		writer.close();
	}

	private void encryptIndices(File library, String pass, PublicKey publicKey)
			throws IOException {
		for (var name : INDICES) {
			var input = new File(library, name + ".bin");
			if (!input.exists())
				continue;
			var output = new File(library, name + ".enc");
			Crypto.encrypt(pass, publicKey.getEncoded(), input, output);
			Files.delete(input.toPath());
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
