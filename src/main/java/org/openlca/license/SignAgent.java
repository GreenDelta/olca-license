package org.openlca.license;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import static org.openlca.license.LicenseGenerator.JSON;

public class SignAgent {

	public static final String ALGORITHM = "SHA256withRSA";
	public static final String SIGNATURE = "signature";

	public static byte[] signFolder(File folder, PrivateKey key)
			throws SignatureException {
		try {
			var signAgent = Signature.getInstance(ALGORITHM);
			signAgent.initSign(key);

			try (var walk = Files.walk(folder.toPath())) {
				walk.filter(Files::isRegularFile)
						.forEach(path -> updateFile(path, signAgent));
			}

			return signAgent.sign();
		} catch (NoSuchAlgorithmException | InvalidKeyException | IOException |
						 SignatureException e) {
			throw new SignatureException("Error while signing the library", e);
		}
	}

	public static boolean verifySignature(File folder, byte[] signature,
			PublicKey key) throws IOException {
		try {
			var signAgent = Signature.getInstance(ALGORITHM);

			signAgent.initVerify(key);

			try (var walk = Files.walk(folder.toPath())) {
				walk.filter(Files::isRegularFile)
						.filter(path -> !path.getFileName().toString().equals(JSON))
						.forEach(path -> updateFile(path, signAgent));
			}

			return signAgent.verify(signature);
		} catch (NoSuchAlgorithmException | InvalidKeyException |
						 SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	private static void updateFile(Path path, Signature signAgent) {
		try {
			var bytes = Files.readAllBytes(path);
			signAgent.update(bytes);
		} catch (IOException | SignatureException e) {
			throw new RuntimeException("Error while signing the following file: "
					+ path.getFileName(), e);
		}
	}

}
