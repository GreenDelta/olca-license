package org.openlca.license;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.BadPaddingException;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


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
	public static List<String> INDICES = Arrays.asList("index_A", "index_B", "index_C");
	public static final int BUFFER_SIZE = 8_192;


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
	 * Construct a new instance of {@link Licensor} with a certificate authority
	 * as an input.
	 * </p>
	 * <p>
	 * The industrial standard for a CA file structure is as follow:
	 *   <ul>
	 *     <li>
	 *       private
	 *       <ul>
	 *         <li>[folder libName].key</li>
	 *       </ul>
	 *     </li>
	 *     <li>[folder libName].crt</li>
	 *   </ul>
	 * </p>
	 */
	public static Licensor getInstance(File ca) throws
			IOException {
		String certificateName = ca.getName() + ".crt";
		PEMParser parser = getPEMParser(new File(ca, certificateName));
		X509CertificateHolder certificate = (X509CertificateHolder) parser.readObject();

		PublicKey publicKey = getPublicKeyCA(certificate);
		PrivateKey privateKey = getPrivateKeyCA(ca);

		if (privateKey == null) {
			throw new IOException("Error while getting the private key from the "
					+ "certificate authority folder.");
		}
		return new Licensor(certificate, publicKey, privateKey);
	}

	/**
	 * <p>
	 * Creates a license framework (certificate, signatures and encryption) from
	 * a data library.
	 * </p>
	 * <p>
	 * The ZIP streams should be created with a 'try'-with-resources statement.
	 * </p>
	 *
	 * @param input  the data library as a ZipIntutStream,
	 * @param output the ZipOutputSteam on which the licensed data library is
	 *               written,
	 * @param pass   the user password that is used to encrypt the data library
	 *               indices,
	 * @param info   the information necessary to the creation of the certificate.
	 */
	public void license(ZipInputStream input, ZipOutputStream output, char[] pass,
			CertificateInfo info) throws IOException {
		keyPair = generateKeyPair();

		String certificate = createCertificate(info);
		String authority = getAuthority();
		signer = new Signer(keyPair.getPrivate());

		ZipEntry zipEntry = input.getNextEntry();
		while (zipEntry != null) {
			processEntry(input, output, zipEntry, pass);
			zipEntry = input.getNextEntry();
		}

		Map<String, byte[]> signaturesAsBytes = signer.getSignatures();
		HashMap<String, String> signatures = new HashMap<String, String>();
		signaturesAsBytes.forEach(
				(key, value) -> signatures.put(key, new String(Base64.encode(value))));

		License license = new License(certificate, signatures, authority);
		writeLicenseToJson(license, output);
	}

	/**
	 * Encrypts the designated files, signs and writes to the ZIP output the
	 * designated ZIP entry.
	 */
	private void processEntry(ZipInputStream input, ZipOutputStream output,
			ZipEntry entry, char[] pass) throws IOException {
		String name = entry.getName();
		String baseName = name.substring(0, name.length() - ".bin".length());
		if (INDICES.contains(baseName)) {
			// encrypting the index file
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			try {
				Crypto.encrypt(pass, keyPair.getPublic().getEncoded(), input, bos);
			} catch (BadPaddingException e) {
				throw new RuntimeException("Error while encrypting the following file: "
						+ name, e);
			}

			// signing the encrypted index with a new ZipEntry
			ZipEntry indexEntry = new ZipEntry(baseName + ".enc");
			output.putNextEntry(indexEntry);
			byte[] bytes = bos.toByteArray();
			ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
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
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String json = gson.toJson(license);
		ByteArrayInputStream jsonInput = new ByteArrayInputStream(json.getBytes());

		ZipEntry licenseEntry = new ZipEntry(JSON);
		output.putNextEntry(licenseEntry);
		write(jsonInput, licenseEntry.getName(), output);
	}

	private void write(InputStream input, String name, OutputStream output) {
		byte[] buffer = new byte[BUFFER_SIZE];
		int length;
		try {
			while ((length = input.read(buffer)) >= 0) {
				output.write(buffer, 0, length);
			}
		} catch (IOException e) {
			throw new RuntimeException("Error while writing the following file: "
					+ name, e);
		}
	}

	/**
	 * Returns the Certificate Authority certificate encoded in Base64.
	 */
	private String getAuthority() {
		try {
			return CertificateGenerator.toBase64(getAuthorityCertificate());
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Returns the Certificate Authority certificate as {@link X509Certificate}.
	 */
	public X509Certificate getAuthorityCertificate() {
		try {
			return new JcaX509CertificateConverter()
					.setProvider(BC)
					.getCertificate(certAuthority);
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Creates a new certificate by calling the {@link CertificateGenerator}
	 * instantiated with the certificate authority.
	 */
	public String createCertificate(CertificateInfo info) {
		KeyPair keyPairCA = new KeyPair(publicKeyCA, privateKeyCA);
		CertificateGenerator generator = new CertificateGenerator(certAuthority, keyPairCA);
		X509Certificate x509certificate = generator.createCertificate(info, keyPair);

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
		SubjectPublicKeyInfo publicKeyInfo = cert.getSubjectPublicKeyInfo();
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		return converter.getPublicKey(publicKeyInfo);
	}

	/**
	 * Returns the {@link PrivateKey} from a certificate authority folder
	 * structured in respect with the industry standard:
	 * </p>
	 * <p>
	 * The industrial standard for a CA file structure is as follow:
	 *   <ul>
	 *     <li>
	 *       private
	 *       <ul>
	 *         <li>[folder libName].key</li>
	 *       </ul>
	 *     </li>
	 *     <li>[folder libName].crt</li>
	 *   </ul>
	 * </p>
	 */
	private static PrivateKey getPrivateKeyCA(File ca)
			throws IOException {
		File privateDir = new File(ca, "private");
		String keyName = ca.getName() + ".key";
		PEMParser parser = getPEMParser(new File(privateDir, keyName));

		JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
		Object keyInfo = parser.readObject();
		if (keyInfo instanceof PrivateKeyInfo)
			return converter.getPrivateKey((PrivateKeyInfo) keyInfo);
		else return null;
	}

	public static PEMParser getPEMParser(File file) throws FileNotFoundException {
		FileInputStream stream = new FileInputStream(file);
		InputStreamReader reader = new InputStreamReader(stream);
		return new PEMParser(reader);
	}

	public static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC);
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException("Error while generating the key pair of the "
					+ "license certificate.", e);
		}
	}

}
