package com.example.registrationlogin.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the fingerprint that is stored for a password reset code.
 */
class OtpHasherTest {

    private static final String SECRET = "a-server-side-secret-that-is-not-public";

    @Test
    @DisplayName("Should produce a 64 character lowercase hexadecimal fingerprint")
    void hash_ProducesHexFingerprint() {
        String hash = OtpHasher.hash(SECRET, "123456");

        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"));
    }

    @Test
    @DisplayName("Should be deterministic for the same secret and code")
    void hash_IsDeterministic() {
        assertEquals(OtpHasher.hash(SECRET, "123456"), OtpHasher.hash(SECRET, "123456"));
    }

    @Test
    @DisplayName("Should never reveal the code")
    void hash_DoesNotLeakTheCode() {
        String hash = OtpHasher.hash(SECRET, "123456");

        assertNotEquals("123456", hash);
        assertFalse(hash.contains("123456"));
    }

    @Test
    @DisplayName("Should produce a different fingerprint for a different secret")
    void hash_DiffersPerSecret() {
        assertNotEquals(OtpHasher.hash(SECRET, "123456"),
                OtpHasher.hash("a-different-secret", "123456"));
    }

    @Test
    @DisplayName("Should produce a different fingerprint for a different code")
    void hash_DiffersPerCode() {
        assertNotEquals(OtpHasher.hash(SECRET, "123456"), OtpHasher.hash(SECRET, "654321"));
    }

    @Test
    @DisplayName("Should match the code it was created for")
    void matches_AcceptsTheCorrectCode() {
        String stored = OtpHasher.hash(SECRET, "123456");

        assertTrue(OtpHasher.matches(SECRET, stored, "123456"));
        assertFalse(OtpHasher.matches(SECRET, stored, "000000"));
        assertFalse(OtpHasher.matches(SECRET, stored, "1234567"));
        assertFalse(OtpHasher.matches(SECRET, stored, ""));
    }

    @Test
    @DisplayName("Should not match a fingerprint that was made with another secret")
    void matches_RejectsAFingerprintOfAnotherSecret() {
        String stored = OtpHasher.hash("another-secret", "123456");

        assertFalse(OtpHasher.matches(SECRET, stored, "123456"));
    }

    @Test
    @DisplayName("Should still accept a legacy record that holds the plain code")
    void matches_AcceptsALegacyPlainRecord() {
        // A row written before the hashing migration still holds the code itself. It has to
        // keep working for the rest of its lifetime.
        assertTrue(OtpHasher.matches(SECRET, "123456", "123456"));
        assertFalse(OtpHasher.matches(SECRET, "123456", "000000"));
    }

    @Test
    @DisplayName("Should reject a missing stored value or code")
    void matches_RejectsMissingInput() {
        assertFalse(OtpHasher.matches(SECRET, null, "123456"));
        assertFalse(OtpHasher.matches(SECRET, OtpHasher.hash(SECRET, "123456"), null));
    }

    @Test
    @DisplayName("Should require a secret and a code")
    void hash_RejectsMissingInput() {
        assertThrows(IllegalArgumentException.class, () -> OtpHasher.hash(null, "123456"));
        assertThrows(IllegalArgumentException.class, () -> OtpHasher.hash("", "123456"));
        assertThrows(IllegalArgumentException.class, () -> OtpHasher.hash(SECRET, null));
    }

    @Test
    @DisplayName("Should be separated from other uses of the same secret")
    void hash_IsDomainSeparated() {
        // The same secret used for something else must not produce the same fingerprint.
        assertNotEquals(OtpHasher.hash(SECRET, "123456"),
                OtpHasher.hash(SECRET, "registration-login:otp:v1:123456"));
    }
}
