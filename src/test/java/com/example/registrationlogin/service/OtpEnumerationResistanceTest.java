package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.ForgotPasswordRequest;
import com.example.registrationlogin.dto.VerifyOtpRequest;
import com.example.registrationlogin.entity.PasswordResetOtp;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
import com.example.registrationlogin.util.OtpHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Proves that the password-recovery endpoints cannot be used to find out whether an address
 * is registered.
 *
 * <p>The decisive test compares the complete sequence of answers for a registered address
 * with the sequence for an unregistered one. They have to be identical, message for message -
 * not merely "similar".</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpEnumerationResistanceTest {

    private static final String KNOWN = "known@example.com";
    private static final String UNKNOWN = "unknown@example.com";

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

    private UserServiceImpl userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        sampleUser = new User("John Doe", KNOWN, "9876543210", "$2a$10$hashedPasswordSample");
        sampleUser.setId(42L);

        JwtUtils jwtUtils = new JwtUtils();
        EmailService emailService = new EmailService(mailSender, "test@example.com");
        doNothing().when(mailSender).send(any(org.springframework.mail.SimpleMailMessage.class));

        OtpRateLimiter rateLimiter = new OtpRateLimiter();
        rateLimiter.setVerifyMaxPerWindow(20);
        rateLimiter.setRequestMaxPerWindow(20);

        userService = new UserServiceImpl(userRepository, otpRepository, passwordEncoder, jwtUtils,
                new TokenBlacklistService(), emailService, new SessionService(sessionRepository), rateLimiter);
    }

    /** Collects the answers of four wrong verification attempts. */
    private List<String> verificationAnswers(String identifier, boolean registered) {
        List<String> answers = new ArrayList<>();

        when(userRepository.findByEmailOrMobileNumber(eq(identifier), anyString()))
                .thenReturn(registered ? Optional.of(sampleUser) : Optional.empty());

        for (int attempt = 1; attempt <= 4; attempt++) {
            try {
                userService.verifyOtp(new VerifyOtpRequest(identifier, "000000"));
                answers.add("OK");
            } catch (RuntimeException ex) {
                answers.add(ex.getMessage());
            }
        }

        return answers;
    }

    @Test
    @DisplayName("Should answer a registered and an unregistered address in exactly the same way")
    void verifyOtp_AnswersIdenticallyForRegisteredAndUnregisteredAddresses() {
        // Both addresses have a pending code record, as they would after a request.
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(anyString()))
                .thenAnswer(invocation -> {
                    PasswordResetOtp otp = new PasswordResetOtp(invocation.getArgument(0),
                            OtpHasher.hash(OtpHasher.DEFAULT_SECRET, "123456"),
                            LocalDateTime.now().plusMinutes(5));
                    otp.setAttempts(0);
                    return Optional.of(otp);
                });

        List<String> registered = verificationAnswers(KNOWN, true);
        List<String> unregistered = verificationAnswers(UNKNOWN, false);

        assertEquals(registered, unregistered,
                "The answers must not differ between a registered and an unregistered address");
        assertFalse(registered.isEmpty());
    }

    @Test
    @DisplayName("Should answer the same way when no code was ever requested")
    void verifyOtp_AnswersIdenticallyWithoutAPendingCode() {
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(anyString())).thenReturn(Optional.empty());

        List<String> registered = verificationAnswers(KNOWN, true);
        List<String> unregistered = verificationAnswers(UNKNOWN, false);

        assertEquals(registered, unregistered,
                "The answers must not differ between a registered and an unregistered address");
        assertEquals("No active OTP request found. Please request a new OTP.", registered.get(0));
    }

    @Test
    @DisplayName("Should answer the same way for an expired code")
    void verifyOtp_AnswersIdenticallyForAnExpiredCode() {
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc(anyString()))
                .thenAnswer(invocation -> {
                    PasswordResetOtp otp = new PasswordResetOtp(invocation.getArgument(0),
                            OtpHasher.hash(OtpHasher.DEFAULT_SECRET, "123456"),
                            LocalDateTime.now().minusMinutes(1));
                    otp.setAttempts(0);
                    return Optional.of(otp);
                });

        List<String> registered = verificationAnswers(KNOWN, true);
        List<String> unregistered = verificationAnswers(UNKNOWN, false);

        assertEquals(registered, unregistered);
        assertEquals("OTP has expired. Please request a new OTP.", registered.get(0));
    }

    @Test
    @DisplayName("Should write a decoy record for an unknown address but send no mail")
    void forgotPassword_WritesADecoyRecordAndSendsNoMail() {
        when(userRepository.findByEmailOrMobileNumber(eq(UNKNOWN), anyString()))
                .thenReturn(Optional.empty());

        userService.forgotPassword(new ForgotPasswordRequest(UNKNOWN));

        verify(otpRepository, times(1)).save(any(PasswordResetOtp.class));
        verify(mailSender, never()).send(any(org.springframework.mail.SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should treat an address that differs only in case as the same address")
    void forgotPassword_NormalisesTheIdentifier() {
        when(userRepository.findByEmailOrMobileNumber(anyString(), anyString())).thenReturn(Optional.empty());

        userService.forgotPassword(new ForgotPasswordRequest("  Unknown@Example.COM  "));

        verify(otpRepository).deleteByIdentifier("unknown@example.com");
        verify(otpRepository).save(argThat(otp -> "unknown@example.com".equals(otp.getIdentifier())));
    }

    @Test
    @DisplayName("Should never accept the code of another address")
    void forgotPassword_StoresADifferentCodeForEveryRequest() {
        when(userRepository.findByEmailOrMobileNumber(eq(UNKNOWN), anyString()))
                .thenReturn(Optional.empty());

        userService.forgotPassword(new ForgotPasswordRequest(UNKNOWN));
        userService.forgotPassword(new ForgotPasswordRequest(UNKNOWN));

        var captor = org.mockito.ArgumentCaptor.forClass(PasswordResetOtp.class);
        verify(otpRepository, times(2)).save(captor.capture());

        List<String> fingerprints = captor.getAllValues().stream()
                .map(PasswordResetOtp::getOtpHash)
                .toList();
        assertNotEquals(fingerprints.get(0), fingerprints.get(1),
                "Every request must produce a different code");
    }
}
