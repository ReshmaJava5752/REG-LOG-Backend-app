package com.example.registrationlogin.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Produces a stable, one-way fingerprint of a bearer token.
 *
 * <p>The {@code sessions} table stores a fingerprint of the JWT instead of the token itself.
 * A JWT is a bearer credential: anybody who can read it can impersonate the account, so the
 * raw value is never written to the database. Because SHA-256 is a one-way function, the
 * stored fingerprint cannot be turned back into a usable token.</p>
 *
 * <p>SHA-256 is used because it is always available on every supported JVM, needs no salt and
 * no key material, and is fast enough to run on every authenticated request. The input is a
 * high-entropy, signed JWT, so a plain digest is appropriate here (unlike for a user-chosen
 * password, which is handled by BCrypt).</p>
 */
public final class TokenHasher {

    private static final String ALGORITHM = "SHA-256";

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    private TokenHasher() {
        // Utility class - not instantiable.
    }

    /**
     * Computes the lowercase hexadecimal SHA-256 fingerprint of the given token.
     *
     * @param token the raw bearer token (never {@code null})
     * @return a 64 character hexadecimal string
     */
    public static String sha256Hex(String token) {
        if (token == null) {
            throw new IllegalArgumentException("Token must not be null.");
        }

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            // SHA-256 is mandated by the Java platform, so this cannot happen in practice.
            throw new IllegalStateException("SHA-256 is not available on this JVM.", ex);
        }

        byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
        char[] hex = new char[hash.length * 2];

        for (int i = 0; i < hash.length; i++) {
            hex[i * 2] = HEX_DIGITS[(hash[i] >> 4) & 0x0F];
            hex[(i * 2) + 1] = HEX_DIGITS[hash[i] & 0x0F];
        }

        return new String(hex);
    }
}
