package com.example.registrationlogin.service;

import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.entity.UserSession;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.util.TokenHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests for the persistent session store.
 *
 * <p>The repository is mocked, so no database row is created or removed by this test class.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SessionServiceTest {

    private static final String TOKEN = "header.payload.signature";
    private static final String TOKEN_HASH = TokenHasher.sha256Hex(TOKEN);

    @Mock
    private UserSessionRepository sessionRepository;

    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        sessionService = new SessionService(sessionRepository);
    }

    private User user(long id) {
        User user = new User("John Doe", "john@example.com", "9876543210", "$2a$10$hashed");
        user.setId(id);
        return user;
    }

    private UserSession activeSession(long userId) {
        return new UserSession(userId, TOKEN_HASH,
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
    }

    // ------------------------------------------------------------------ register

    @Test
    @DisplayName("Should store only the token fingerprint and never the raw token")
    void registerSession_StoresOnlyTheFingerprint() {
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString())).thenReturn(Optional.empty());
        Date expiry = new Date(System.currentTimeMillis() + 86_400_000L);

        sessionService.registerSession(user(42L), TOKEN, expiry);

        ArgumentCaptor<UserSession> captor = ArgumentCaptor.forClass(UserSession.class);
        verify(sessionRepository, times(1)).save(captor.capture());

        UserSession saved = captor.getValue();
        assertEquals(42L, saved.getUserId());
        assertEquals(TOKEN_HASH, saved.getTokenHash());
        assertNotEquals(TOKEN, saved.getTokenHash());
        assertNull(saved.getJwtToken(), "The raw bearer token must never be persisted");
        assertFalse(saved.getIsRevoked());
        assertNotNull(saved.getLoginTime());
        assertNotNull(saved.getExpiryTime());
    }

    @Test
    @DisplayName("Should re-use an existing row instead of writing a duplicate")
    void registerSession_ReusesExistingRow() {
        UserSession existing = activeSession(42L);
        existing.setId(7L);
        existing.revoke();

        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TOKEN_HASH)).thenReturn(Optional.of(existing));

        sessionService.registerSession(user(42L), TOKEN, new Date(System.currentTimeMillis() + 86_400_000L));

        verify(sessionRepository, times(1)).save(any(UserSession.class));
        assertFalse(existing.getIsRevoked(), "A fresh login re-activates the session");
        assertNull(existing.getRevokedAt());
    }

    @Test
    @DisplayName("Should ignore a blank token")
    void registerSession_IgnoresBlankToken() {
        sessionService.registerSession(user(42L), "  ", new Date());

        verify(sessionRepository, never()).save(any(UserSession.class));
    }

    // ---------------------------------------------------------------- isActive

    @Test
    @DisplayName("Should accept a token that has no session record (graceful cutover)")
    void isSessionActive_AcceptsTokenWithoutSessionRecord() {
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString())).thenReturn(Optional.empty());

        assertTrue(sessionService.isSessionActive(TOKEN),
                "A token issued before persistent sessions were enabled stays valid until it expires");
    }

    @Test
    @DisplayName("Should accept an active session")
    void isSessionActive_AcceptsActiveSession() {
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TOKEN_HASH))
                .thenReturn(Optional.of(activeSession(42L)));

        assertTrue(sessionService.isSessionActive(TOKEN));
    }

    @Test
    @DisplayName("Should reject a revoked session")
    void isSessionActive_RejectsRevokedSession() {
        UserSession revoked = activeSession(42L);
        revoked.revoke();

        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TOKEN_HASH))
                .thenReturn(Optional.of(revoked));

        assertFalse(sessionService.isSessionActive(TOKEN));
    }

    @Test
    @DisplayName("Should reject an expired session")
    void isSessionActive_RejectsExpiredSession() {
        UserSession expired = new UserSession(42L, TOKEN_HASH,
                LocalDateTime.now().minusHours(2), LocalDateTime.now().minusHours(1));

        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TOKEN_HASH))
                .thenReturn(Optional.of(expired));

        assertFalse(sessionService.isSessionActive(TOKEN));
    }

    @Test
    @DisplayName("Should fall back to the in-memory list when the session store is unavailable")
    void isSessionActive_DegradesWhenStoreUnavailable() {
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString()))
                .thenThrow(new DataAccessResourceFailureException("sessions table unavailable"));

        assertTrue(sessionService.isSessionActive(TOKEN),
                "A broken session store must not lock every user out");
    }

    // ------------------------------------------------------------------ revoke

    @Test
    @DisplayName("Should revoke the stored session on logout")
    void revokeSession_MarksTheSessionRevoked() {
        UserSession session = activeSession(42L);
        session.setId(3L);
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TOKEN_HASH))
                .thenReturn(Optional.of(session));

        boolean revoked = sessionService.revokeSession(TOKEN);

        assertTrue(revoked);
        assertTrue(session.getIsRevoked());
        assertNotNull(session.getRevokedAt());
        verify(sessionRepository, times(1)).save(session);
    }

    @Test
    @DisplayName("Should ignore a token that has no session record")
    void revokeSession_IgnoresUnknownToken() {
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString())).thenReturn(Optional.empty());

        assertFalse(sessionService.revokeSession(TOKEN));
        verify(sessionRepository, never()).save(any(UserSession.class));
    }

    @Test
    @DisplayName("Should revoke every active session of a user")
    void revokeAllSessions_RevokesEveryActiveSession() {
        UserSession first = activeSession(42L);
        UserSession second = activeSession(42L);
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(42L)).thenReturn(List.of(first, second));

        int revoked = sessionService.revokeAllSessions(42L);

        assertEquals(2, revoked);
        assertTrue(first.getIsRevoked());
        assertTrue(second.getIsRevoked());
        verify(sessionRepository, times(1)).saveAll(List.of(first, second));
    }

    @Test
    @DisplayName("Should do nothing when the user has no active session")
    void revokeAllSessions_HandlesNoActiveSession() {
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(anyLong())).thenReturn(List.of());

        assertEquals(0, sessionService.revokeAllSessions(42L));
        verify(sessionRepository, never()).saveAll(any());
    }

    // ------------------------------------------------------------------- purge

    @Test
    @DisplayName("Should remove expired session records")
    void purgeExpiredSessions_RemovesExpiredRows() {
        when(sessionRepository.deleteByExpiryTimeBefore(any(LocalDateTime.class))).thenReturn(4L);

        assertEquals(4, sessionService.purgeExpiredSessions());
        verify(sessionRepository, times(1)).deleteByExpiryTimeBefore(any(LocalDateTime.class));
    }

    // --------------------------------------------------------- disabled service

    @Test
    @DisplayName("Should behave as before persistent sessions when the store is disabled")
    void disabledService_IsANoOp() {
        SessionService disabled = SessionService.disabled();

        assertTrue(disabled.isSessionActive(TOKEN));
        assertFalse(disabled.revokeSession(TOKEN));
        assertEquals(0, disabled.revokeAllSessions(42L));
        assertEquals(0L, disabled.countActiveSessions(42L));
        assertEquals(0, disabled.purgeExpiredSessions());

        disabled.registerSession(user(42L), TOKEN, new Date());

        verifyNoInteractions(sessionRepository);
    }
}
