package com.example.registrationlogin.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the token fingerprint used by the persistent session store.
 */
class TokenHasherTest {

    @Test
    @DisplayName("Should produce a 64 character lowercase hexadecimal fingerprint")
    void sha256Hex_ProducesHexFingerprint() {
        String hash = TokenHasher.sha256Hex("header.payload.signature");

        assertEquals(64, hash.length(), "A SHA-256 fingerprint must be 64 hex characters long");
        assertTrue(hash.matches("[0-9a-f]{64}"), "The fingerprint must be lowercase hexadecimal");
    }

    @Test
    @DisplayName("Should be deterministic for the same token")
    void sha256Hex_IsDeterministic() {
        String token = "header.payload.signature";

        assertEquals(TokenHasher.sha256Hex(token), TokenHasher.sha256Hex(token));
    }

    @Test
    @DisplayName("Should never reveal the original token")
    void sha256Hex_DoesNotLeakTheToken() {
        String token = "header.payload.signature";

        String hash = TokenHasher.sha256Hex(token);

        assertNotEquals(token, hash);
        assertFalse(hash.contains(token));
    }

    @Test
    @DisplayName("Should produce different fingerprints for different tokens")
    void sha256Hex_DiffersPerToken() {
        assertNotEquals(TokenHasher.sha256Hex("token-one"), TokenHasher.sha256Hex("token-two"));
    }

    @Test
    @DisplayName("Should match the well known SHA-256 digest of the empty string")
    void sha256Hex_MatchesKnownVector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                TokenHasher.sha256Hex(""));
    }

    @Test
    @DisplayName("Should reject a null token")
    void sha256Hex_RejectsNull() {
        assertThrows(IllegalArgumentException.class, () -> TokenHasher.sha256Hex(null));
    }
}
