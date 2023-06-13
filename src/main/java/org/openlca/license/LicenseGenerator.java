package org.openlca.license;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.openlca.license.certificate.CertificateGenerator;
import org.openlca.license.certificate.LicenseInfo;
import org.openlca.license.crypto.Crypto;
import org.openlca.license.crypto.CryptoException;
import org.openlca.license.signature.SignAgent;
import org.openlca.license.signature.SignAgentException;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;


/**
 * <p>
 *   The LicenseGenerator class is used to generate the license elements of a
 *   data library. A license generator is constructed by calling the static
 *   method {@code getInstance} with a certificate authority as input.
 * </p>
 * <p>
 *   The licensing of a data library consists in three operations:
 *   <ol>
 *     <li>creation of a X509 certificate signed by the issuer certificate
 *     authority with the information of the owner,</li>
 *     <li>symmetric encryption of the data indices with a key generated with
 *     the user password,</li>
 *     <li>signature of the data library with the above-mentioned certificate
 *     private key.</li>
 *   </ol>
 * </p>
 *
 * In order to sign a data library, one can use the following lines:
 * <p>
 * <code>
 * var generator = LicenseGenerator.getInstance(CertAuthFileInputStream);
 * var licensedLib = generator.doLicensing(libraryFIS, licenseInfo, password);
 * </code>
 *
 */
public class LicenseGenerator {

	private static final String BC = "BC";
	private static final String KEY_ALGORITHM = "RSA";
	public static final String SALT_FILE = "license.salt";
	public static final String CERT_FILE = "license.crt";
	public static final String SIGN_FILE = "license.sig";
	public static List<String> INDICES = List.of("index_A", "index_B", "index_C");

	public final X509CertificateHolder certAuthority;
	public final PrivateKey privateKeyCA;
	public PublicKey publicKeyCA;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public LicenseGenerator(X509CertificateHolder ca, PublicKey publicKey,
			PrivateKey privateKey) {
		certAuthority = ca;
		publicKeyCA = publicKey;
		privateKeyCA = privateKey;
	}

	public static LicenseGenerator getInstance(File caDir)
			throws IOException, OperatorCreationException, PKCSException {
		var parser = getPEMParser(new File(caDir, caDir.getName() + ".crt"));
		var certificate = (X509CertificateHolder) parser.readObject();

		var publicKey = getPublicKeyCA(certificate);
		var privateKey = getPrivateKeyCA(caDir);
		return new LicenseGenerator(certificate, publicKey, privateKey);
	}

	public File doLicensing(File library, LicenseInfo info, String password)
			throws LicenseException {
		try {
			var keyPair = generateKeyPair();
			var certificate = createCertificate(info, keyPair);

			CertificateGenerator.writeCertToBase64(certificate, library, CERT_FILE);

			var salt = encryptIndices(library, password);
			storeFile(library, salt, SALT_FILE);

			var signature = SignAgent.signFolder(library, keyPair.getPrivate());
			if (!SignAgent.verifySignature(library, signature, keyPair.getPublic())) {
				throw  new LicenseException("The signature could not be "
						+ "verified");
			}
			storeFile(library, signature, SIGN_FILE);

			return library;
		} catch (CertificateException | SignatureException | SignAgentException e) {
			throw new LicenseException("Error while licensing the library", e);
		}
	}

	private byte[] encryptIndices(File library, String password)
			throws LicenseException {
		try {
			var salt = Crypto.generateSalt();

			for (var name : INDICES) {
				var input = new File(library, name + ".bin");
				if (!input.exists())
					continue;
				var output = new File(library, name + ".enc");
				Crypto.encrypt(password, salt, input, output);
				Files.delete(input.toPath());
			}
			return salt;
		} catch (IOException | CryptoException e) {
			throw new LicenseException("Error while encrypting the indices", e);
		}
	}

	private void storeFile(File library, byte[] salt, String name)
			throws LicenseException {
		var outputFile = new File(library, name);
		try (var outputStream = new FileOutputStream(outputFile)) {
			outputStream.write(salt);
		} catch (IOException e) {
			throw new LicenseException("Error while storing " + name, e);
		}
	}

	public X509Certificate createCertificate(LicenseInfo info, KeyPair keyPair)
			throws CertificateException {
		var keyPairCA = new KeyPair(publicKeyCA, privateKeyCA);
		var generator = new CertificateGenerator(certAuthority, keyPairCA);

		return generator.createCertificate(info, keyPair);
	}

	private static PublicKey getPublicKeyCA(X509CertificateHolder cert)
			throws PEMException {
		var publicKeyInfo = cert.getSubjectPublicKeyInfo();
		var converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(publicKeyInfo);
	}

	private static PrivateKey getPrivateKeyCA(File caDir)
			throws IOException, OperatorCreationException, PKCSException {
		var privateDir = new File(caDir, "private");
		var keyName = caDir.getName() + ".key";
		var parser = getPEMParser(new File(privateDir, keyName));

		var converter = new JcaPEMKeyConverter();
		if (parser.readObject() instanceof PKCS8EncryptedPrivateKeyInfo keyInfo) {
			// Encrypted key - we will use provided password
			var password = getPassword(caDir);
			var decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
					.setProvider(BC)
					.build(password);
			var privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);
			return converter.getPrivateKey(privateKeyInfo);
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

	public static KeyPair generateKeyPair() throws LicenseException {
		try {
			// Generate a new KeyPair and sign it using the CA private key by
			// generating a CSR (Certificate Signing Request)
			var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC);
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new LicenseException("Error while generating the key pair", e);
		}
	}

}
