package org.openlca.license.access;

import java.util.Objects;

/**
 * @param user the username or the email of the user.
 * @param password the password of the user.
 */
public class Credentials {

	private final String user;
	private final char[] password;

	public Credentials(String user, char[] password) {
		this.user = user;
		this.password = password;
	}

	public String user() {
		return user;
	}

	public char[] password() {
		return password;
	}

	@Override
	public int hashCode() {
		return Objects.hash(user, password);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (!(obj instanceof Credentials))
			return false;
		Credentials other = (Credentials) obj;
		return Objects.equals(user, other.user)
				&& Objects.equals(password, other.password);
	}

}
