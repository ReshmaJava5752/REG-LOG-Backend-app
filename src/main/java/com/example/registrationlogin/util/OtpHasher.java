package com.example.registrationlogin.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

/**
 * Produces the fingerprint that is stored for a password-reset OTP.
 *
 * <p><b>Why a plain digest is not enough:</b> a reset code is only six digits, so there are
 * exactly one million possibilities. A plain SHA-256 of the code would be trivial to brute
 * force: anybody who could read the {@code password_reset_otps} table could try all one
 * million candidates in seconds and recover the code of any pending request.</p>
 *
 * <p><b>Why an HMAC:</b> the fingerprint is computed with a server-side secret that never
 * leaves the backend. Without that secret an attacker who reads the table cannot compute the
 * fingerprint of any candidate code, so the one million possibilities cannot be searched at
 * all. This is the same reason the password is protected by BCrypt, adapted to the very low
 * entropy of a numeric code.</p>
 *
 * <p>The message is prefixed with a fixed context string, so the same secret can safely be
 * used for other purposes without the fingerprints colliding.</p>
 */
public final class OtpHasher {

    /**
     * The fallback secret used when nothing is configured. It matches the fallback of
     * {@code app.jwt.secret} and only exists so that the application starts without a
     * configuration file; a deployment must set a real secret.
     */
    public static final String DEFAULT_SECRET = "CHANGE_ME_IN_PRODUCTION_CHANGE_ME_IN_PRODUCTION";

    /** Domain separation - keeps these fingerprints apart from any other use of the secret. */
    private static final String CONTEXT = "registration-login:otp:v1:";

    private static final String ALGORITHM = "HmacSHA256";

    private OtpHasher() {
        // Utility class - not instantiable.
    }

    /**
     * Computes the fingerprint that is stored for the given reset code.
     *
     * @param secret  the server-side secret (never the empty string)
     * @param otpCode the plain reset code
     * @return a 64 character lowercase hexadecimal fingerprint
     */
    public static String hash(String secret, String otpCode) {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("A secret is required to fingerprint an OTP.");
        }
        if (otpCode == null) {
            throw new IllegalArgumentException("An OTP code is required.");
        }

        Mac mac;
        try {
            mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM));
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            // HmacSHA256 is mandated by the Java platform, so this cannot happen in practice.
            throw new IllegalStateException("HmacSHA256 is not available on this JVM.", ex);
        }

        byte[] digest = mac.doFinal((CONTEXT + otpCode).getBytes(StandardCharsets.UTF_8));

        char[] hex = new char[digest.length * 2];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < digest.length; i++) {
            hex[i * 2] = digits[(digest[i] >> 4) & 0x0F];
            hex[(i * 2) + 1] = digits[digest[i] & 0x0F];
        }
        return new String(hex);
    }

    /**
     * Checks a submitted reset code against the value that is stored for it.
     *
     * <p>The comparison is constant time, so it does not leak how many characters matched.</p>
     *
     * <p>Rows that were written <em>before</em> the hashing migration still contain the plain
     * code. Those rows are accepted as well, so that a code which was requested shortly before
     * the migration keeps working for the rest of its (five minute) lifetime. The application
     * never writes a plain code itself.</p>
     *
     * @param secret      the server-side secret
     * @param storedValue the value read from the database
     * @param otpCode     the code submitted by the client
     * @return {@code true} when the code is the one that was issued
     */
    public static boolean matches(String secret, String storedValue, String otpCode) {
        if (storedValue == null || otpCode == null) {
            return false;
        }

        if (constantTimeEquals(hash(secret, otpCode), storedValue)) {
            return true;
        }

        // Legacy row, written before the hashing migration.
        return constantTimeEquals(otpCode, storedValue);
    }

    /**
     * Compares two strings without leaking their contents through the time the comparison takes.
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
