package org.openlca.license.signature;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *   The Signer class is used to sign a set of files with a {@link PrivateKey}.
 * </p>
 */
public class Signer {

	public static final String ALGORITHM = "SHA256withRSA";
	public static final int BUFFER_SIZE = 8192;

	private final Signature agent;
	private final Map<String, byte[]> signatures;

	public Signer(PrivateKey key) {
		signatures = new HashMap<>();
		try {
			agent = Signature.getInstance(ALGORITHM);
			agent.initSign(key);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException("Error while initiating the signature agent "
					+ "for signing actions.", e);
		}
	}

	/**
	 * <p>
	 *   This method takes an {@link InputStream}, a file name as well as
	 *   an {@link OutputStream} and do two things:
	 *   <ul>
	 *     <li>recursively updates the bytes of the file to be signed,</li>
	 *     <li>write the {@link InputStream} to the {@link OutputStream}
	 *     (optional if the {@link OutputStream} is <code>null</code>).</li>
	 *   </ul>
	 * </p>
	 */
	public void sign(InputStream in, String name, OutputStream out) throws
			IOException {
		var buffer = new byte[BUFFER_SIZE];
		int length;
		while ((length = in.read(buffer)) >= 0) {
			if (out != null) {
				out.write(buffer, 0, length);
			}
			try {
				agent.update(buffer, 0, length);
			} catch (SignatureException e) {
				throw new RuntimeException("Error while signing the following entry: "
						+ name, e);
			}
		}

		try {
			signatures.put(name, agent.sign());
		} catch (SignatureException e) {
			throw new RuntimeException("Error while finalizing the signature of the "
					+ "following entry: " + name, e);
		}
	}

	public Map<String, byte[]> getSignatures() {
		return signatures;
	}

}
