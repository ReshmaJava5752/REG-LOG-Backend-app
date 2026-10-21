package com.example.registrationlogin.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the account-wide token revocation.
 *
 * <p>The interesting case is the boundary: a JWT only carries second precision, so a token
 * that was issued in the same second as the revocation must not be rejected.</p>
 */
class TokenBlacklistServiceTest {

    private TokenBlacklistService tokenBlacklistService;

    private void setUp() {
        tokenBlacklistService = new TokenBlacklistService();
    }

    @Test
    @DisplayName("Should report a token that was issued before the revocation as revoked")
    void isUserTokenRevokedBefore_RevokesOlderTokens() {
        setUp();
        long now = System.currentTimeMillis();

        tokenBlacklistService.revokeAllUserTokens("john@example.com");

        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", now - 2000),
                "A token that was issued two seconds earlier must be revoked");
    }

    @Test
    @DisplayName("Should not revoke a token that was issued in the same second as the revocation")
    void isUserTokenRevokedBefore_KeepsATokenFromTheSameSecond() {
        setUp();
        long now = System.currentTimeMillis();

        tokenBlacklistService.revokeAllUserTokens("john@example.com");

        // The JWT carries second precision, so this token was issued in the same second as the
        // revocation - possibly even after it. It must not be rejected.
        assertFalse(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", now - (now % 1000)),
                "A token from the same second must not be revoked");
    }

    @Test
    @DisplayName("Should not revoke a token that was issued after the revocation")
    void isUserTokenRevokedBefore_KeepsNewerTokens() {
        setUp();
        long now = System.currentTimeMillis();

        tokenBlacklistService.revokeAllUserTokens("john@example.com");

        assertFalse(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", now + 5000));
    }

    @Test
    @DisplayName("Should ignore an identifier that was never revoked")
    void isUserTokenRevokedBefore_IgnoresUnknownIdentifiers() {
        setUp();

        assertFalse(tokenBlacklistService.isUserTokenRevokedBefore("nobody@example.com",
                System.currentTimeMillis() - 10000));
    }

    @Test
    @DisplayName("Should treat the identifier case insensitively")
    void isUserTokenRevokedBefore_NormalisesTheIdentifier() {
        setUp();
        long now = System.currentTimeMillis();

        tokenBlacklistService.revokeAllUserTokens("John@Example.com");

        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", now - 2000));
    }

    @Test
    @DisplayName("Should blacklist a token and report it as blacklisted")
    void isBlacklisted_ReportsBlacklistedTokens() {
        setUp();
        String token = "header.payload.signature";

        assertFalse(tokenBlacklistService.isBlacklisted(token));

        tokenBlacklistService.blacklistToken(token, System.currentTimeMillis() + 60_000);

        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }

    @Test
    @DisplayName("Should stop reporting a token once it has expired")
    void isBlacklisted_ForgetsExpiredTokens() {
        setUp();
        String token = "header.payload.signature";

        tokenBlacklistService.blacklistToken(token, System.currentTimeMillis() - 1);

        assertFalse(tokenBlacklistService.isBlacklisted(token));
    }
}
