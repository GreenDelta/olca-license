package org.openlca.license;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class SignatureAgent {

	public static final String ALGORITHM = "SHA256withRSA";
	public static final int BUFFER_SIZE = 1024;

	public static class Signer {

		private final java.security.Signature agent;
		private final Map<String, byte[]> signatures;

		public Signer(PrivateKey key) {
			signatures = new HashMap<>();
			try {
				agent = java.security.Signature.getInstance(ALGORITHM);
				agent.initSign(key);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new RuntimeException("Error while initiating the signature agent "
						+ "for signing actions.", e);
			}
		}

		public void write(InputStream in, ZipEntry entry, ZipOutputStream out)
				throws IOException {
			out.putNextEntry(entry);

			var buffer = new byte[BUFFER_SIZE];
			int length;
			while ((length = in.read(buffer)) >= 0) {
				out.write(buffer, 0, length);
				try {
					agent.update(buffer);
				} catch (SignatureException e) {
					throw new RuntimeException("Error while signing the following entry: "
							+ entry.getName(), e);
				}
			}

			try {
				signatures.put(entry.getName(), agent.sign());
			} catch (SignatureException e) {
				throw new RuntimeException("Error while finalizing the signature.", e);
			}
		}

		public Map<String, byte[]> getSignatures() {
			return signatures;
		}

	}

	public static class Verifier {

		private final java.security.Signature agent;
		private final Map<String, byte[]> signatures;

		public Verifier(PublicKey key, Map<String, byte[]> signatures) {
			this.signatures = signatures;
			try {
				agent = java.security.Signature.getInstance(ALGORITHM);
				agent.initVerify(key);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				throw new RuntimeException("Error while initiating the signature agent "
						+ "for verification actions.", e);
			}
		}

		public boolean verify(File folder, List<Path> blackList)
				throws IOException {
			if (!signatures.keySet().stream()
					.map(name -> new File(folder, name))
					.allMatch(File::exists))
				return false;

			try (var walk = Files.walk(folder.toPath())) {
				return walk.filter(Files::isRegularFile)
						.filter(Predicate.not(blackList::contains))
						.allMatch(this::verifyFile);
			}


		}

		public boolean verify(File folder)
				throws IOException {
			return verify(folder, new ArrayList<>());
		}

		private boolean verifyFile(Path path) {
			var signature = signatures.get(path.getFileName().toString());
			if (signature == null)
				return false;

			try (var fis = new FileInputStream(path.toFile())) {
				var buffer = new byte[BUFFER_SIZE];
				while ((fis.read(buffer)) >= 0) {
					agent.update(buffer);
				}
				return agent.verify(signature);
			} catch (SignatureException | IOException e) {
				throw new RuntimeException("Error while signing the following file: "
						+ path.getFileName(), e);
			}
		}

	}

}
