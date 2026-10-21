package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.*;
import com.example.registrationlogin.entity.PasswordResetOtp;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.entity.UserSession;
import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
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
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Tests that the authentication flows drive the persistent session store: a login records a
 * session, a logout revokes it, and a password change or reset revokes every session of the
 * account.
 *
 * <p>The real {@link SessionService} is used and only the {@link UserSessionRepository}
 * interface is mocked, so the actual session logic runs while no database row is written.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserServiceSessionTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetOtpRepository otpRepository;

    @Mock
    private UserSessionRepository sessionRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JavaMailSender mailSender;

    private JwtUtils jwtUtils;
    private TokenBlacklistService tokenBlacklistService;
    private UserServiceImpl userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        sampleUser = new User("John Doe", "john@example.com", "9876543210", "$2a$10$hashedPasswordSample");
        sampleUser.setId(42L);
        sampleUser.setCreatedAt(LocalDateTime.now());
        sampleUser.setUpdatedAt(LocalDateTime.now());

        jwtUtils = new JwtUtils();
        tokenBlacklistService = new TokenBlacklistService();
        EmailService emailService = new EmailService(mailSender, "test@example.com");
        doNothing().when(mailSender).send(any(org.springframework.mail.javamail.MimeMessagePreparator.class));

        SessionService sessionService = new SessionService(sessionRepository);
        userService = new UserServiceImpl(userRepository, otpRepository, passwordEncoder, jwtUtils,
                tokenBlacklistService, emailService, sessionService);
    }

    private UserSession activeSession() {
        return new UserSession(42L, "f".repeat(64),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
    }

    // ------------------------------------------------------------------- login

    @Test
    @DisplayName("Should record a session when a user logs in")
    void login_RecordsTheSession() {
        LoginRequest request = new LoginRequest("john@example.com", "Secret@123");
        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Secret@123", sampleUser.getPassword())).thenReturn(true);
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString())).thenReturn(Optional.empty());

        AuthResponse response = userService.authenticateUser(request);

        assertNotNull(response.getToken());
        ArgumentCaptor<UserSession> captor = ArgumentCaptor.forClass(UserSession.class);
        verify(sessionRepository, times(1)).save(captor.capture());

        UserSession saved = captor.getValue();
        assertEquals(42L, saved.getUserId());
        assertEquals(TokenHasher.sha256Hex(response.getToken()), saved.getTokenHash());
        assertNull(saved.getJwtToken(), "The raw bearer token must never be persisted");
        assertFalse(saved.getIsRevoked());
    }

    @Test
    @DisplayName("Should still return a token when the session store is unavailable")
    void login_SurvivesASessionStoreFailure() {
        LoginRequest request = new LoginRequest("john@example.com", "Secret@123");
        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Secret@123", sampleUser.getPassword())).thenReturn(true);
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString()))
                .thenThrow(new DataAccessResourceFailureException("sessions table unavailable"));

        AuthResponse response = assertDoesNotThrow(() -> userService.authenticateUser(request));

        assertNotNull(response.getToken());
    }

    // ------------------------------------------------------------------ logout

    @Test
    @DisplayName("Should revoke the stored session on logout")
    void logout_RevokesTheStoredSession() {
        String token = jwtUtils.generateToken("john@example.com");
        UserSession session = new UserSession(42L, TokenHasher.sha256Hex(token),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(TokenHasher.sha256Hex(token)))
                .thenReturn(Optional.of(session));

        userService.logout(token);

        assertTrue(session.getIsRevoked(), "The stored session must be marked as revoked");
        assertNotNull(session.getRevokedAt());
        verify(sessionRepository, times(1)).save(session);
        assertTrue(tokenBlacklistService.isBlacklisted(token),
                "The in-memory revocation list must still be updated");
    }

    @Test
    @DisplayName("Should keep the in-memory revocation when the session store fails on logout")
    void logout_StillRevokesInMemoryWhenTheSessionStoreFails() {
        String token = jwtUtils.generateToken("john@example.com");
        when(sessionRepository.findFirstByTokenHashOrderByIdDesc(anyString()))
                .thenThrow(new DataAccessResourceFailureException("sessions table unavailable"));

        assertDoesNotThrow(() -> userService.logout(token));

        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }

    // ------------------------------------------------------------ password reset

    @Test
    @DisplayName("Should revoke every stored session of the account on password reset")
    void resetPassword_RevokesEveryStoredSession() {
        ResetPasswordRequest request = new ResetPasswordRequest("john@example.com",
                "valid-reset-token", "NewPass@123", "NewPass@123");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456",
                LocalDateTime.now().plusMinutes(5));
        otp.setIsVerified(true);
        otp.setResetToken("valid-reset-token");

        UserSession first = activeSession();
        UserSession second = activeSession();

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findByIdentifierAndResetToken("john@example.com", "valid-reset-token"))
                .thenReturn(Optional.of(otp));
        when(passwordEncoder.encode("NewPass@123")).thenReturn("$2a$10$newHashedPassword");
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(42L)).thenReturn(List.of(first, second));

        userService.resetPassword(request);

        assertTrue(first.getIsRevoked(), "Every stored session must be revoked after a password reset");
        assertTrue(second.getIsRevoked());
        verify(sessionRepository, times(1)).saveAll(List.of(first, second));
        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com",
                System.currentTimeMillis() - 1000));
    }

    // ---------------------------------------------------------- password change

    @Test
    @DisplayName("Should revoke every stored session of the account on password change")
    void changePassword_RevokesEveryStoredSession() {
        ChangePasswordRequest request = new ChangePasswordRequest("Current@123", "BrandNew@123", "BrandNew@123");

        UserSession first = activeSession();
        UserSession second = activeSession();

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Current@123", sampleUser.getPassword())).thenReturn(true);
        when(passwordEncoder.encode("BrandNew@123")).thenReturn("$2a$10$brandNewHashedPassword");
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(42L)).thenReturn(List.of(first, second));

        userService.changePassword("john@example.com", request);

        assertTrue(first.getIsRevoked(), "Every stored session must be revoked after a password change");
        assertTrue(second.getIsRevoked());
        verify(sessionRepository, times(1)).saveAll(List.of(first, second));
        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com",
                System.currentTimeMillis() - 1000));
    }

    @Test
    @DisplayName("Should still revoke the sessions in memory when the session store fails")
    void resetPassword_KeepsTheInMemoryRevocationWhenTheStoreFails() {
        ResetPasswordRequest request = new ResetPasswordRequest("john@example.com",
                "valid-reset-token", "NewPass@123", "NewPass@123");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456",
                LocalDateTime.now().plusMinutes(5));
        otp.setIsVerified(true);
        otp.setResetToken("valid-reset-token");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findByIdentifierAndResetToken("john@example.com", "valid-reset-token"))
                .thenReturn(Optional.of(otp));
        when(passwordEncoder.encode("NewPass@123")).thenReturn("$2a$10$newHashedPassword");
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(anyLong()))
                .thenThrow(new DataAccessResourceFailureException("sessions table unavailable"));

        assertDoesNotThrow(() -> userService.resetPassword(request));

        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com",
                System.currentTimeMillis() - 1000));
    }
}
