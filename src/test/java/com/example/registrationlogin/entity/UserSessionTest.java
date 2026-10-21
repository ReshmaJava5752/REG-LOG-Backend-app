package com.example.registrationlogin.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the persistent session record.
 */
class UserSessionTest {

    @Test
    @DisplayName("Should default to an active session with the given timestamps")
    void constructor_SetsActiveSession() {
        LocalDateTime loginTime = LocalDateTime.of(2026, 3, 1, 9, 0, 0);
        LocalDateTime expiryTime = LocalDateTime.of(2026, 3, 2, 9, 0, 0);

        UserSession session = new UserSession(42L, "a".repeat(64), loginTime, expiryTime);

        assertEquals(42L, session.getUserId());
        assertEquals("a".repeat(64), session.getTokenHash());
        assertEquals(loginTime, session.getLoginTime());
        assertEquals(expiryTime, session.getExpiryTime());
        assertFalse(session.getIsRevoked());
        assertNull(session.getRevokedAt());
    }

    @Test
    @DisplayName("Should report an unrevoked, unexpired session as active")
    void isActiveAt_ReturnsTrueForActiveSession() {
        LocalDateTime now = LocalDateTime.of(2026, 3, 1, 12, 0, 0);
        UserSession session = new UserSession(42L, "a".repeat(64),
                now.minusHours(1), now.plusHours(1));

        assertTrue(session.isActiveAt(now));
    }

    @Test
    @DisplayName("Should report a revoked session as inactive")
    void isActiveAt_ReturnsFalseForRevokedSession() {
        LocalDateTime now = LocalDateTime.of(2026, 3, 1, 12, 0, 0);
        UserSession session = new UserSession(42L, "a".repeat(64),
                now.minusHours(1), now.plusHours(1));

        session.revoke();

        assertFalse(session.isActiveAt(now));
    }

    @Test
    @DisplayName("Should report an expired session as inactive")
    void isActiveAt_ReturnsFalseForExpiredSession() {
        LocalDateTime now = LocalDateTime.of(2026, 3, 1, 12, 0, 0);
        UserSession session = new UserSession(42L, "a".repeat(64),
                now.minusHours(2), now.minusHours(1));

        assertFalse(session.isActiveAt(now));
    }

    @Test
    @DisplayName("Should stamp the revocation time when a session is revoked")
    void revoke_StampsTheRevocationTime() {
        UserSession session = new UserSession(42L, "a".repeat(64),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));

        session.revoke();

        assertTrue(session.getIsRevoked());
        assertNotNull(session.getRevokedAt());
    }

    @Test
    @DisplayName("Should apply defaults on insert")
    void prePersist_AppliesDefaults() {
        UserSession session = new UserSession();
        session.setUserId(42L);
        session.setTokenHash("b".repeat(64));

        session.onCreate();

        assertNotNull(session.getLoginTime());
        assertFalse(session.getIsRevoked());
    }
}
