package org.openlca.license;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

public class LicenseGenerator {

	private static final String CA_PATH = "nexus-ca/nexus-ca.crt";
	private static final String PRIVATE_CA_PATH = "nexus-ca/private/nexus-ca.key";
	private static final String BC = "BC";
	private static final String PASSWORD_PATH = "nexus-ca/nexus.pass";
	private final Logger log = LoggerFactory.getLogger(getClass());
	public final X509CertificateHolder certificateAuthority;
	public final PrivateKey privateKeyCA;
	public final PublicKey publicKeyCA;


	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public LicenseGenerator() {
		certificateAuthority = getCertificateAuthority();
		publicKeyCA = getPublicKeyCA();
		privateKeyCA = getPrivateKeyCA();

		if (privateKeyCA != null && publicKeyCA != null) {
			var keyPair = new KeyPair(publicKeyCA, privateKeyCA);
			var generator = new CertificateGenerator(certificateAuthority, keyPair);
			generator.createCertificate();
		}
	}

	private PublicKey getPublicKeyCA() {
		var publicKeyInfo = certificateAuthority.getSubjectPublicKeyInfo();
		var converter = new JcaPEMKeyConverter();

		try {
			return converter.getPublicKey(publicKeyInfo);
		} catch (PEMException e) {
			log.error("Error while reading the public key.", e);
			return null;
		}
	}

	private PrivateKey getPrivateKeyCA() {
		var parser = getPEMParser(PRIVATE_CA_PATH);
		var converter = new JcaPEMKeyConverter();
		if (parser == null)
			return null;

		try {
			if (parser.readObject() instanceof PKCS8EncryptedPrivateKeyInfo keyInfo) {
				// Encrypted key - we will use provided password
				var password = getPassword();
				if (password != null) {
					var decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
							.setProvider(BC)
							.build(password);
					var privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);
					return converter.getPrivateKey(privateKeyInfo);
				}
			}
			return null;
		} catch (Exception e) {
			log.error("Error while reading the private key.", e);
			return null;
		}
	}

	private char[] getPassword() {
		try {
			var buffer = new BufferedReader(new FileReader(PASSWORD_PATH));
			var password = buffer.readLine();
			return password.toCharArray();
		} catch (IOException e) {
			log.error("Error while reading the password.", e);
			return null;
		}
	}

	public X509CertificateHolder getCertificateAuthority() {
		var parser = getPEMParser(CA_PATH);

		if (parser == null)
			return null;

		try {
			if (parser.readObject() instanceof X509CertificateHolder cert)
				return cert;
			else return null;
		} catch (IOException e) {
			log.error("Error while reading the Root Certificate", e);
			return null;
		}
	}

	public PEMParser getPEMParser(String path) {
		try {
			var stream = new FileInputStream(path);
			var reader = new InputStreamReader(stream);
			return new PEMParser(reader);
		} catch (FileNotFoundException e) {
			log.error("Error while parsing the PEM file.", e);
			return null;
		}
	}

}
