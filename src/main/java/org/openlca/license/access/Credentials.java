package org.openlca.license.access;

/**
 * @param user the username or the email of the user.
 * @param password the password of the user.
 */
public record Credentials(String user, char[] password) {}
