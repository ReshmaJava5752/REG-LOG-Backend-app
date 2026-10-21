package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.*;
import com.example.registrationlogin.entity.PasswordResetOtp;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.entity.UserSession;
import com.example.registrationlogin.exception.TooManyRequestsException;
import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
import com.example.registrationlogin.util.OtpHasher;
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
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * End-to-end tests of the password-recovery flow: requesting a code, its expiry, invalid
 * codes, the rate limits, a successful reset and the invalidation of the account's sessions.
 *
 * <p>Only the repository interfaces are mocked, so the real rate limiter and the real
 * revocation logic run while no database row is written.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserServiceOtpTest {

    private static final String EMAIL = "john@example.com";
    private static final String MOBILE = "9876543210";

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
    private OtpRateLimiter otpRateLimiter;
    private UserServiceImpl userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        sampleUser = new User("John Doe", EMAIL, MOBILE, "$2a$10$hashedPasswordSample");
        sampleUser.setId(42L);
        sampleUser.setCreatedAt(LocalDateTime.now());
        sampleUser.setUpdatedAt(LocalDateTime.now());

        jwtUtils = new JwtUtils();
        tokenBlacklistService = new TokenBlacklistService();
        EmailService emailService = new EmailService(mailSender, "test@example.com");
        doNothing().when(mailSender).send(any(org.springframework.mail.javamail.MimeMessagePreparator.class));

        otpRateLimiter = new OtpRateLimiter();
        otpRateLimiter.setRequestMaxPerWindow(3);
        otpRateLimiter.setRequestWindowMinutes(15);
        otpRateLimiter.setVerifyMaxPerWindow(5);
        otpRateLimiter.setVerifyWindowMinutes(15);

        userService = new UserServiceImpl(userRepository, otpRepository, passwordEncoder, jwtUtils,
                tokenBlacklistService, emailService, new SessionService(sessionRepository), otpRateLimiter);
    }

    private void givenRegisteredUser() {
        when(userRepository.findByEmailOrMobileNumber(eq(EMAIL), anyString()))
                .thenReturn(Optional.of(sampleUser));
    }

    private PasswordResetOtp storedOtp(String code, LocalDateTime expiry) {
        // The record holds the fingerprint of the code, exactly like the service writes it.
        PasswordResetOtp otp = new PasswordResetOtp(EMAIL, OtpHasher.hash(OtpHasher.DEFAULT_SECRET, code), expiry);
        otp.setAttempts(0);
        return otp;
    }

    // -------------------------------------------------------------- requesting

    @Test
    @DisplayName("Should generate and deliver a code by e-mail when a code is requested")
    void forgotPassword_GeneratesAndDeliversTheCode() {
        givenRegisteredUser();

        userService.forgotPassword(new ForgotPasswordRequest(EMAIL));

        ArgumentCaptor<PasswordResetOtp> captor = ArgumentCaptor.forClass(PasswordResetOtp.class);
        verify(otpRepository, times(1)).save(captor.capture());

        PasswordResetOtp saved = captor.getValue();
        assertEquals(EMAIL, saved.getIdentifier());
        assertTrue(saved.getOtpHash().matches("^[0-9a-f]{64}$"),
                "The database must hold a 64 character fingerprint, not the code itself");
        assertFalse(saved.getOtpHash().matches("^[0-9]{6}$"),
                "The plain code must never be written to the database");
        assertTrue(saved.getExpiryTime().isAfter(LocalDateTime.now().plusMinutes(4)),
                "The code must be valid for about 5 minutes");
        verify(mailSender, times(1)).send(any(org.springframework.mail.SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should not deliver anything for an unknown identifier but still answer generically")
    void forgotPassword_UnknownIdentifier_DeliversNothing() {
        when(userRepository.findByEmailOrMobileNumber(eq("nobody@example.com"), anyString()))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() -> userService.forgotPassword(new ForgotPasswordRequest("nobody@example.com")));

        // No mail is sent for an unknown address - that is the only user visible difference.
        verify(mailSender, never()).send(any(org.springframework.mail.SimpleMailMessage.class));

        // A decoy record is written, so that the verification endpoint cannot be used to
        // find out whether the address is registered.
        ArgumentCaptor<PasswordResetOtp> captor = ArgumentCaptor.forClass(PasswordResetOtp.class);
        verify(otpRepository, times(1)).save(captor.capture());
        assertEquals("nobody@example.com", captor.getValue().getIdentifier());
        assertTrue(captor.getValue().getOtpHash().matches("^[0-9a-f]{64}$"));
    }

    // ------------------------------------------------------- rate limiting

    @Test
    @DisplayName("Should reject repeated requests for the same account once the limit is reached")
    void forgotPassword_RateLimitsRepeatedRequests() {
        givenRegisteredUser();

        for (int i = 0; i < 3; i++) {
            assertDoesNotThrow(() -> userService.forgotPassword(new ForgotPasswordRequest(EMAIL)));
        }

        TooManyRequestsException exception = assertThrows(TooManyRequestsException.class,
                () -> userService.forgotPassword(new ForgotPasswordRequest(EMAIL)));

        assertTrue(exception.getRetryAfterSeconds() > 0, "The response must tell the client when to retry");
        assertFalse(exception.getMessage().contains(EMAIL), "The message must not contain the identifier");
    }

    @Test
    @DisplayName("Should rate limit unknown identifiers exactly like known ones")
    void forgotPassword_RateLimitsUnknownIdentifiersToo() {
        when(userRepository.findByEmailOrMobileNumber(eq("nobody@example.com"), anyString()))
                .thenReturn(Optional.empty());

        for (int i = 0; i < 3; i++) {
            assertDoesNotThrow(() -> userService.forgotPassword(new ForgotPasswordRequest("nobody@example.com")));
        }

        assertThrows(TooManyRequestsException.class,
                () -> userService.forgotPassword(new ForgotPasswordRequest("nobody@example.com")),
                "An unknown identifier must be throttled like a known one so accounts cannot be enumerated");
    }

    @Test
    @DisplayName("Should count the e-mail and the mobile number of one account as the same key")
    void forgotPassword_UsesTheCanonicalAccountAsKey() {
        givenRegisteredUser();
        when(userRepository.findByEmailOrMobileNumber(eq(MOBILE), anyString()))
                .thenReturn(Optional.of(sampleUser));

        userService.forgotPassword(new ForgotPasswordRequest(EMAIL));
        userService.forgotPassword(new ForgotPasswordRequest(MOBILE));

        assertEquals(2, otpRateLimiter.countFor(OtpRateLimiter.SCOPE_REQUEST, EMAIL),
                "The mobile number and the e-mail of one account must share a counter");
    }

    @Test
    @DisplayName("Should reject repeated verification attempts once the limit is reached")
    void verifyOtp_RateLimitsRepeatedAttempts() {
        givenRegisteredUser();
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(EMAIL))
                .thenReturn(Optional.of(storedOtp("123456", LocalDateTime.now().plusMinutes(5))));

        for (int i = 0; i < 5; i++) {
            assertDoesNotThrow(() -> {
                try {
                    userService.verifyOtp(new VerifyOtpRequest(EMAIL, "000000"));
                } catch (IllegalArgumentException ignored) {
                    // The wrong-code failure is expected; only the rate limit matters here.
                }
            });
        }

        assertThrows(TooManyRequestsException.class,
                () -> userService.verifyOtp(new VerifyOtpRequest(EMAIL, "000000")));
    }

    // -------------------------------------------------------------- verifying

    @Test
    @DisplayName("Should reject an expired code")
    void verifyOtp_RejectsAnExpiredCode() {
        givenRegisteredUser();
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(EMAIL))
                .thenReturn(Optional.of(storedOtp("123456", LocalDateTime.now().minusMinutes(1))));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> userService.verifyOtp(new VerifyOtpRequest(EMAIL, "123456")));

        assertTrue(exception.getMessage().contains("expired"));
    }

    @Test
    @DisplayName("Should reject an invalid code and count the attempt")
    void verifyOtp_RejectsAnInvalidCode() {
        givenRegisteredUser();
        PasswordResetOtp otp = storedOtp("123456", LocalDateTime.now().plusMinutes(5));
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(EMAIL)).thenReturn(Optional.of(otp));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> userService.verifyOtp(new VerifyOtpRequest(EMAIL, "000000")));

        assertTrue(exception.getMessage().contains("Invalid OTP code"));
        assertEquals(1, otp.getAttempts(), "A wrong code must count as an attempt");
        verify(otpRepository, times(1)).save(otp);
    }

    @Test
    @DisplayName("Should not roll back the attempt counter when a wrong code is rejected")
    void verifyOtp_MustCommitTheAttemptCounter() throws Exception {
        // The counter is written before the exception is raised. With the default rollback rule
        // the transaction would be discarded and the counter would stay at zero for ever,
        // which would silently disable the limit on the number of attempts.
        Transactional transactional = UserServiceImpl.class
                .getMethod("verifyOtp", VerifyOtpRequest.class)
                .getAnnotation(Transactional.class);

        assertNotNull(transactional, "verifyOtp must run in a transaction");
        assertTrue(Arrays.asList(transactional.noRollbackFor()).contains(IllegalArgumentException.class),
                "A rejected code must not roll back the attempt counter");
    }

    @Test
    @DisplayName("Should issue a single-use reset token for the correct code")
    void verifyOtp_IssuesAResetToken() {
        givenRegisteredUser();
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(EMAIL))
                .thenReturn(Optional.of(storedOtp("123456", LocalDateTime.now().plusMinutes(5))));

        String resetToken = userService.verifyOtp(new VerifyOtpRequest(EMAIL, "123456"));

        assertNotNull(resetToken);
        assertFalse(resetToken.isBlank());
    }

    // -------------------------------------------------------------- resetting

    @Test
    @DisplayName("Should reset the password and revoke every session of the account")
    void resetPassword_ResetsThePasswordAndRevokesTheSessions() {
        givenRegisteredUser();

        PasswordResetOtp otp = storedOtp("123456", LocalDateTime.now().plusMinutes(5));
        otp.setIsVerified(true);
        otp.setResetToken("valid-reset-token");

        UserSession first = new UserSession(42L, "f".repeat(64),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));
        UserSession second = new UserSession(42L, "e".repeat(64),
                LocalDateTime.now().minusHours(1), LocalDateTime.now().plusHours(1));

        when(otpRepository.findByIdentifierAndResetToken(EMAIL, "valid-reset-token"))
                .thenReturn(Optional.of(otp));
        when(passwordEncoder.encode("NewPass@123")).thenReturn("$2a$10$newHashedPassword");
        when(sessionRepository.findAllByUserIdAndIsRevokedFalse(42L)).thenReturn(List.of(first, second));

        userService.resetPassword(new ResetPasswordRequest(EMAIL, "valid-reset-token", "NewPass@123", "NewPass@123"));

        verify(passwordEncoder, times(1)).encode("NewPass@123");
        assertEquals("$2a$10$newHashedPassword", sampleUser.getPassword());
        assertTrue(first.getIsRevoked(), "The sessions of the account must be revoked");
        assertTrue(second.getIsRevoked());
        verify(otpRepository, times(1)).delete(otp);
        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore(EMAIL, System.currentTimeMillis() - 1000),
                "The tokens of the account must be revoked in the in-memory list as well");
    }

    @Test
    @DisplayName("Should refuse to reset the password with an unverified code")
    void resetPassword_RejectsAnUnverifiedCode() {
        givenRegisteredUser();

        PasswordResetOtp otp = storedOtp("123456", LocalDateTime.now().plusMinutes(5));
        otp.setResetToken("valid-reset-token");

        when(otpRepository.findByIdentifierAndResetToken(EMAIL, "valid-reset-token"))
                .thenReturn(Optional.of(otp));

        assertThrows(IllegalArgumentException.class, () -> userService.resetPassword(
                new ResetPasswordRequest(EMAIL, "valid-reset-token", "NewPass@123", "NewPass@123")));

        verify(passwordEncoder, never()).encode(anyString());
    }

    @Test
    @DisplayName("Should refuse to reset the password with an unknown reset token")
    void resetPassword_RejectsAnUnknownResetToken() {
        givenRegisteredUser();

        when(otpRepository.findByIdentifierAndResetToken(EMAIL, "made-up"))
                .thenReturn(Optional.empty());

        assertThrows(IllegalArgumentException.class, () -> userService.resetPassword(
                new ResetPasswordRequest(EMAIL, "made-up", "NewPass@123", "NewPass@123")));

        verify(passwordEncoder, never()).encode(anyString());
    }
}
