package org.openlca.license;

import com.google.gson.GsonBuilder;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Base64;
import org.openlca.license.certificate.CertificateGenerator;
import org.openlca.license.certificate.CertificateInfo;
import org.openlca.license.signature.Signer;

import javax.crypto.BadPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
 *     <li>creation of a X.509 certificate signed by the issuer certificate
 *     authority with the information of the owner,</li>
 *     <li>symmetric encryption of the data indices with a key generated with
 *     the user password and certificate public key as salt,</li>
 *     <li>signature of the data library with the above-mentioned certificate
 *     private key.</li>
 *   </ol>
 * </p>
 */
public class Licensor {

	private static final String BC = "BC";
	private static final String KEY_ALGORITHM = "RSA";
	public static final String JSON = "license.json";
	public static List<String> INDICES = List.of("index_A", "index_B", "index_C");
	public static final int BUFFER_SIZE = 8192;


	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public final X509CertificateHolder certAuthority;
	public final PrivateKey privateKeyCA;
	public final PublicKey publicKeyCA;

	private KeyPair keyPair;
	private Signer signer;

	private Licensor(X509CertificateHolder ca, PublicKey publicKey,
			PrivateKey privateKey) {
		certAuthority = ca;
		publicKeyCA = publicKey;
		privateKeyCA = privateKey;
	}

	/**
	 * <p>
	 *   Construct a new instance of {@link Licensor} with a certificate authority
	 *   as an input.
	 * </p>
	 * <p>
	 *   The industrial standard for a CA file structure is as follow:
	 *   <ul>
	 *     <li>
	 *       private
	 *       <ul>
	 *         <li>[folder name].key</li>
	 *       </ul>
	 *     </li>
	 *     <li>[folder name].crt</li>
	 *   </ul>
	 * </p>
	 */
	public static Licensor getInstance(File ca) throws
			IOException {
		var certificateName = ca.getName() + ".crt";
		var parser = getPEMParser(new File(ca, certificateName));
		var certificate = (X509CertificateHolder) parser.readObject();

		var publicKey = getPublicKeyCA(certificate);
		var privateKey = getPrivateKeyCA(ca);

		if (privateKey == null) {
			throw new IOException("Error while getting the private key from the "
					+ "certificate authority folder.");
		}
		return new Licensor(certificate, publicKey, privateKey);
	}

	/**
	 * <p>
	 *   Creates a license framework (certificate, signatures and encryption) from
	 *   a data library.
	 * </p>
	 * <p>
	 *   The ZIP streams should be created with a 'try'-with-resources statement.
	 * </p>
	 *
	 * @param input the data library as a ZipIntutStream,
	 * @param output the ZipOutputSteam on which the licensed data library is
	 *               written,
	 * @param pass the user password that is used to encrypt the data library
	 *             indices,
	 * @param info the information necessary to the creation of the certificate.
	 */
	public void license(ZipInputStream input, ZipOutputStream output, char[] pass,
			CertificateInfo info) throws IOException {
		keyPair = generateKeyPair();

		var certificate = createCertificate(info);
		var authority = getAuthority();
		signer = new Signer(keyPair.getPrivate());

		var zipEntry = input.getNextEntry();
		while (zipEntry != null) {
			processEntry(input, output, zipEntry, pass);
			zipEntry = input.getNextEntry();
		}

		var signaturesAsBytes = signer.getSignatures();
		var signatures = new HashMap<String, String>();
		signaturesAsBytes.forEach(
				(key, value) -> signatures.put(key, new String(Base64.encode(value))));

		var license = new License(certificate, signatures, authority);
		writeLicenseToJson(license, output);
	}

	/**
	 * Encrypts the designated files, signs and writes to the ZIP output the
	 * designated ZIP entry.
	 */
	private void processEntry(ZipInputStream input, ZipOutputStream output,
			ZipEntry entry, char[] pass) throws IOException {
		var name = entry.getName();
		var baseName = name.substring(0, name.length() - ".bin".length());
		if (INDICES.contains(baseName)) {
			// encrypting the index file
			var bos = new ByteArrayOutputStream();
			try {
				Crypto.encrypt(pass, keyPair.getPublic().getEncoded(), input, bos);
			} catch (BadPaddingException e) {
				throw new RuntimeException("Error while encrypting the following file: "
						+ name, e);
			}

			// signing the encrypted index with a new ZipEntry
			var indexEntry = new ZipEntry(baseName + ".enc");
			output.putNextEntry(indexEntry);
			var bytes = bos.toByteArray();
			var bis = new ByteArrayInputStream(bytes);
			signer.sign(bis, indexEntry.getName(), output);
		} else {
			output.putNextEntry(entry);
			signer.sign(input, name, output);
		}
	}

	/**
	 * Writes the {@link License} object to a JSON file saved into the library
	 * folder.
	 */
	private void writeLicenseToJson(License license, ZipOutputStream output)
			throws IOException {
		var gson = new GsonBuilder().setPrettyPrinting().create();
		var json = gson.toJson(license);
		var jsonInput = new ByteArrayInputStream(json.getBytes());

		var licenseEntry = new ZipEntry(JSON);
		output.putNextEntry(licenseEntry);
		var buffer = new byte[BUFFER_SIZE];
		int length;
		while((length = jsonInput.read(buffer)) >= 0) {
			output.write(buffer, 0, length);
		}
	}

	/**
	 * Returns the Certificate Authority certificate encoded in Base64.
	 */
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

	/**
	 * Creates a new certificate by calling the {@link CertificateGenerator}
	 * instantiated with the certificate authority.
	 */
	public String createCertificate(CertificateInfo info) {
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

	/**
	 * Returns the {@link PublicKey} of a certificate.
	 */
	private static PublicKey getPublicKeyCA(X509CertificateHolder cert)
			throws PEMException {
		var publicKeyInfo = cert.getSubjectPublicKeyInfo();
		var converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(publicKeyInfo);
	}

	/**
	 * Returns the {@link PrivateKey} from a certificate authority folder
	 * structured in respect with the industry standard:
	 * </p>
	 * <p>
	 *   The industrial standard for a CA file structure is as follow:
	 *   <ul>
	 *     <li>
	 *       private
	 *       <ul>
	 *         <li>[folder name].key</li>
	 *       </ul>
	 *     </li>
	 *     <li>[folder name].crt</li>
	 *   </ul>
	 * </p>
	 */
	private static PrivateKey getPrivateKeyCA(File ca)
			throws IOException {
		var privateDir = new File(ca, "private");
		var keyName = ca.getName() + ".key";
		var parser = getPEMParser(new File(privateDir, keyName));

		var converter = new JcaPEMKeyConverter();
		if (parser.readObject() instanceof PrivateKeyInfo keyInfo)
			return converter.getPrivateKey(keyInfo);
		else return  null;
	}

	public static PEMParser getPEMParser(File file) throws FileNotFoundException {
		var stream = new FileInputStream(file);
		var reader = new InputStreamReader(stream);
		return new PEMParser(reader);
	}

	public static KeyPair generateKeyPair() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC);
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException("Error while generating the key pair of the "
					+ "license certificate.", e);
		}
	}

}
