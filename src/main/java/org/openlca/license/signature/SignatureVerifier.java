package org.openlca.license.signature;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.openlca.license.signature.Signer.*;


/**
 * <p>
 *   The Verifier class is used to verify the signature of a set of files with
 *   a {@link PublicKey}.
 * </p>
 */
public class SignatureVerifier {

	private final Signature agent;
	private final Map<String, byte[]> signatures;

	public SignatureVerifier(PublicKey key, Map<String, byte[]> signatures) {
		this.signatures = signatures;
		try {
			agent = Signature.getInstance(ALGORITHM);
			agent.initVerify(key);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException("Error while initiating the signature agent "
					+ "for verification actions.", e);
		}
	}

	/**
	 * <p>
	 *   This method  do two things:
	 *   <ul>
	 *     <li>check if all the files listed in the signature map exist in
	 *     the input folder,</li>
	 *     <li>check if all the files of the folder have a valid signature.</li>
	 *   </ul>
	 * </p>
	 *
	 * @param folder the folder with the set of file to verify.
	 * @param blacklist a list of {@link Path}s that should be excluded from the
	 *                  signature check (useful if the signature file is in the
	 *                  folder).
	 */
	public boolean verify(File folder, List<Path> blacklist) throws IOException {
		// Check if none of the signed files is blacklisted
		var fileNames = signatures.keySet();
		if (blacklist.stream()
				.map(Path::getFileName)
				.map(Path::toString)
				.anyMatch(fileNames::contains)) {
			return false;
		}

		// Check if all the signed files exist
		if (signatures.keySet().stream()
				.map(name -> new File(folder, name))
				.anyMatch(Predicate.not(File::exists)))
			return false;

		// Verify all the signature
		try (var walk = Files.walk(folder.toPath())) {
			return walk
					.filter(Files::isRegularFile)
					.filter(path -> path.toFile().length() < SIZE_LIMIT)
					.filter(Predicate.not(blacklist::contains))
					.allMatch(this::verifyFile);
		}
	}

	/**
	 * An overload of <code>verify</code> method when the blacklist of paths is
	 * empty.
	 */
	public boolean verify(File folder) throws IOException {
		return verify(folder, new ArrayList<>());
	}

	private boolean verifyFile(Path path) {
		var fileName = path.getFileName().toString();
		var signature = signatures.get(fileName);

		// The file might have been added after the signature
		if (signature == null)
			return false;

		try (var fis = new FileInputStream(path.toFile())) {
			var buffer = new byte[BUFFER_SIZE];
			int lenght;
			while ((lenght = fis.read(buffer)) >= 0) {
				agent.update(buffer, 0, lenght);
			}
			return agent.verify(signature);
		} catch (SignatureException | IOException e) {
			throw new RuntimeException("Error while verifying the signature of the "
					+ "following file: " + fileName, e);
		}
	}

}
