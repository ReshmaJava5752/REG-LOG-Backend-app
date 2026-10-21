package com.example.registrationlogin;

import com.example.registrationlogin.dto.*;
import com.example.registrationlogin.entity.PasswordResetOtp;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
import com.example.registrationlogin.service.EmailService;
import com.example.registrationlogin.service.UserServiceImpl;
import org.springframework.mail.javamail.JavaMailSender;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetOtpRepository otpRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private JwtUtils jwtUtils;
    private TokenBlacklistService tokenBlacklistService;
    @Mock
    private JavaMailSender mailSender;
    private EmailService emailService;
    private UserServiceImpl userService;

    private User sampleUser;

    @BeforeEach
    void setUp() {
        sampleUser = new User();
        sampleUser.setId(1L);
        sampleUser.setFullName("John Doe");
        sampleUser.setEmail("john@example.com");
        sampleUser.setMobileNumber("9876543210");
        sampleUser.setPassword("$2a$10$hashedPasswordSample");
        sampleUser.setCreatedAt(LocalDateTime.now());
        sampleUser.setUpdatedAt(LocalDateTime.now());

        jwtUtils = new JwtUtils();
        tokenBlacklistService = new TokenBlacklistService();
        emailService = new EmailService(mailSender, "test@example.com");
        doNothing().when(mailSender).send(any(org.springframework.mail.javamail.MimeMessagePreparator.class));
        userService = new UserServiceImpl(userRepository, otpRepository, passwordEncoder, jwtUtils, tokenBlacklistService, emailService);
    }

    @Test
    @DisplayName("Should successfully register user with valid data, 10-digit mobile, and BCrypt hashed password")
    void registerUser_Success() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "Secret@123", "Secret@123");

        when(userRepository.existsByEmail("john@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(false);
        when(passwordEncoder.encode("Secret@123")).thenReturn("$2a$10$hashedPasswordSample");
        when(userRepository.save(any(User.class))).thenReturn(sampleUser);

        UserResponse response = userService.registerUser(request);

        assertNotNull(response);
        assertEquals("John Doe", response.getFullName());
        assertEquals("john@example.com", response.getEmail());
        assertEquals("9876543210", response.getMobileNumber());
        verify(passwordEncoder, times(1)).encode("Secret@123");
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    @DisplayName("Should fail registration when passwords do not match")
    void registerUser_PasswordMismatch() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "Secret@123", "Different@123");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(request);
        });

        assertEquals("Passwords do not match.", exception.getMessage());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should fail registration when name is less than 3 characters")
    void registerUser_InvalidNameLength() {
        RegisterRequest request = new RegisterRequest("Jo", "john@example.com", "9876543210", "Secret@123", "Secret@123");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(request);
        });

        assertTrue(exception.getMessage().contains("between 3 and 100 characters"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should fail registration when email already exists")
    void registerUser_DuplicateEmail() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "Secret@123", "Secret@123");

        when(userRepository.existsByEmail("john@example.com")).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(request);
        });

        assertTrue(exception.getMessage().contains("already exists"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should fail registration when mobile number already exists")
    void registerUser_DuplicateMobileNumber() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "Secret@123", "Secret@123");

        when(userRepository.existsByEmail("john@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(true);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(request);
        });

        assertTrue(exception.getMessage().contains("mobile number already exists"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should fail registration when password does not meet complexity rules")
    void registerUser_WeakPassword() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "weakpassword", "weakpassword");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.registerUser(request);
        });

        assertTrue(exception.getMessage().contains("at least 8 characters"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should successfully authenticate valid user login with email and return real JWT token")
    void authenticateUser_SuccessWithEmail() {
        LoginRequest request = new LoginRequest("john@example.com", "Secret@123");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Secret@123", sampleUser.getPassword())).thenReturn(true);

        AuthResponse response = userService.authenticateUser(request);

        assertNotNull(response);
        assertNotNull(response.getToken());
        assertTrue(jwtUtils.validateToken(response.getToken()));
        assertEquals("john@example.com", jwtUtils.getIdentifierFromToken(response.getToken()));
        assertEquals("Bearer", response.getTokenType());
        assertNotNull(response.getUser());
        assertEquals("John Doe", response.getUser().getFullName());
        assertEquals("john@example.com", response.getUser().getEmail());
    }

    @Test
    @DisplayName("Should successfully authenticate valid user login with 10-digit mobile number")
    void authenticateUser_SuccessWithMobile() {
        LoginRequest request = new LoginRequest("9876543210", "Secret@123");

        when(userRepository.findByEmailOrMobileNumber("9876543210", "9876543210"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Secret@123", sampleUser.getPassword())).thenReturn(true);

        AuthResponse response = userService.authenticateUser(request);

        assertNotNull(response);
        assertNotNull(response.getToken());
        assertTrue(jwtUtils.validateToken(response.getToken()));
        assertEquals("John Doe", response.getUser().getFullName());
    }

    @Test
    @DisplayName("Should fail login when identifier is not found")
    void authenticateUser_UserNotFound() {
        LoginRequest request = new LoginRequest("unknown@example.com", "Secret@123");

        when(userRepository.findByEmailOrMobileNumber("unknown@example.com", "unknown@example.com"))
                .thenReturn(Optional.empty());

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.authenticateUser(request);
        });

        assertEquals("Invalid email/mobile or password.", exception.getMessage());
    }

    @Test
    @DisplayName("Should fail login when password is incorrect")
    void authenticateUser_IncorrectPassword() {
        LoginRequest request = new LoginRequest("john@example.com", "WrongPassword@123");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("WrongPassword@123", sampleUser.getPassword())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.authenticateUser(request);
        });

        assertEquals("Invalid email/mobile or password.", exception.getMessage());
    }

    @Test
    @DisplayName("Should generate OTP for registered user without throwing error")
    void forgotPassword_Success() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("john@example.com");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));

        assertDoesNotThrow(() -> userService.forgotPassword(request));
        verify(otpRepository, times(1)).deleteByIdentifier("john@example.com");
        verify(otpRepository, times(1)).save(any(PasswordResetOtp.class));
    }

    @Test
    @DisplayName("Should not reveal user non-existence during forgot password")
    void forgotPassword_UserNotFound_DoesNotThrow() {
        ForgotPasswordRequest request = new ForgotPasswordRequest("notfound@example.com");

        when(userRepository.findByEmailOrMobileNumber("notfound@example.com", "notfound@example.com"))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() -> userService.forgotPassword(request));

        // Nothing is delivered for an unknown address - that is the only user visible
        // difference and it is not one. A decoy record is written so that the verification
        // endpoint answers exactly the same way for a known and for an unknown address.
        verify(mailSender, never()).send(any(org.springframework.mail.SimpleMailMessage.class));
        verify(otpRepository, times(1)).save(any(PasswordResetOtp.class));
    }

    @Test
    @DisplayName("Should verify valid OTP and return single-use reset token")
    void verifyOtp_Success() {
        VerifyOtpRequest request = new VerifyOtpRequest("john@example.com", "123456");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456", LocalDateTime.now().plusMinutes(5));
        otp.setAttempts(0);

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc("john@example.com"))
                .thenReturn(Optional.of(otp));

        String resetToken = userService.verifyOtp(request);

        assertNotNull(resetToken);
        assertTrue(otp.getIsVerified());
        assertNotNull(otp.getResetToken());
        verify(otpRepository, times(1)).save(otp);
    }

    @Test
    @DisplayName("Should fail OTP verification when code is invalid and increment attempt count")
    void verifyOtp_InvalidCode() {
        VerifyOtpRequest request = new VerifyOtpRequest("john@example.com", "000000");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456", LocalDateTime.now().plusMinutes(5));
        otp.setAttempts(0);

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc("john@example.com"))
                .thenReturn(Optional.of(otp));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.verifyOtp(request);
        });

        assertTrue(exception.getMessage().contains("Invalid OTP code"));
        assertEquals(1, otp.getAttempts());
        verify(otpRepository, times(1)).save(otp);
    }

    @Test
    @DisplayName("Should fail OTP verification when maximum attempts exceeded")
    void verifyOtp_MaxAttemptsExceeded() {
        VerifyOtpRequest request = new VerifyOtpRequest("john@example.com", "123456");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456", LocalDateTime.now().plusMinutes(5));
        otp.setAttempts(3);

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findTopByIdentifierOrderByCreatedAtDesc("john@example.com"))
                .thenReturn(Optional.of(otp));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.verifyOtp(request);
        });

        assertTrue(exception.getMessage().contains("Maximum verification attempts exceeded"));
    }

    @Test
    @DisplayName("Should successfully reset password with verified reset token and BCrypt hash")
    void resetPassword_Success() {
        ResetPasswordRequest request = new ResetPasswordRequest("john@example.com", "valid-reset-token", "NewPass@123", "NewPass@123");

        PasswordResetOtp otp = new PasswordResetOtp("john@example.com", "123456", LocalDateTime.now().plusMinutes(5));
        otp.setIsVerified(true);
        otp.setResetToken("valid-reset-token");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(otpRepository.findByIdentifierAndResetToken("john@example.com", "valid-reset-token"))
                .thenReturn(Optional.of(otp));
        when(passwordEncoder.encode("NewPass@123")).thenReturn("$2a$10$newHashedPassword");

        assertDoesNotThrow(() -> userService.resetPassword(request));
        verify(passwordEncoder, times(1)).encode("NewPass@123");
        verify(userRepository, times(1)).save(sampleUser);
        verify(otpRepository, times(1)).delete(otp);
        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", System.currentTimeMillis() - 1000));
    }

    @Test
    @DisplayName("Should successfully change password for authenticated user and invalidate active tokens")
    void changePassword_Success() {
        ChangePasswordRequest request = new ChangePasswordRequest("Current@123", "BrandNew@123", "BrandNew@123");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Current@123", sampleUser.getPassword())).thenReturn(true);
        when(passwordEncoder.encode("BrandNew@123")).thenReturn("$2a$10$brandNewHashedPassword");

        assertDoesNotThrow(() -> userService.changePassword("john@example.com", request));
        verify(passwordEncoder, times(1)).encode("BrandNew@123");
        verify(userRepository, times(1)).save(sampleUser);
        assertTrue(tokenBlacklistService.isUserTokenRevokedBefore("john@example.com", System.currentTimeMillis() - 1000));
    }

    @Test
    @DisplayName("Should fail change password when current password is wrong")
    void changePassword_IncorrectCurrentPassword() {
        ChangePasswordRequest request = new ChangePasswordRequest("WrongCurrent@123", "BrandNew@123", "BrandNew@123");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("WrongCurrent@123", sampleUser.getPassword())).thenReturn(false);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            userService.changePassword("john@example.com", request);
        });

        assertTrue(exception.getMessage().contains("Current password is incorrect"));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should successfully blacklist JWT token on logout")
    void logout_Success() {
        String token = jwtUtils.generateToken("john@example.com");
        assertTrue(jwtUtils.validateToken(token));
        assertFalse(tokenBlacklistService.isBlacklisted(token));

        userService.logout(token);

        assertTrue(tokenBlacklistService.isBlacklisted(token));
    }

    @Test
    @DisplayName("Should return createdAt and updatedAt timestamps when registering a user")
    void registerUser_ReturnsCreatedAndUpdatedTimestamps() {
        RegisterRequest request = new RegisterRequest("John Doe", "john@example.com", "9876543210", "Secret@123", "Secret@123");

        when(userRepository.existsByEmail("john@example.com")).thenReturn(false);
        when(userRepository.existsByMobileNumber("9876543210")).thenReturn(false);
        when(passwordEncoder.encode("Secret@123")).thenReturn("$2a$10$hashedPasswordSample");
        when(userRepository.save(any(User.class))).thenReturn(sampleUser);

        UserResponse response = userService.registerUser(request);

        assertNotNull(response.getCreatedAt(), "createdAt must be returned to the API client");
        assertNotNull(response.getUpdatedAt(), "updatedAt must be returned to the API client");
        assertEquals(sampleUser.getCreatedAt(), response.getCreatedAt());
        assertEquals(sampleUser.getUpdatedAt(), response.getUpdatedAt());
    }

    @Test
    @DisplayName("Should return createdAt and updatedAt timestamps when logging in")
    void authenticateUser_ReturnsCreatedAndUpdatedTimestamps() {
        LoginRequest request = new LoginRequest("john@example.com", "Secret@123");

        when(userRepository.findByEmailOrMobileNumber("john@example.com", "john@example.com"))
                .thenReturn(Optional.of(sampleUser));
        when(passwordEncoder.matches("Secret@123", sampleUser.getPassword())).thenReturn(true);

        AuthResponse response = userService.authenticateUser(request);

        assertNotNull(response.getUser().getCreatedAt(), "createdAt must be returned to the API client");
        assertNotNull(response.getUser().getUpdatedAt(), "updatedAt must be returned to the API client");
        assertEquals(sampleUser.getUpdatedAt(), response.getUser().getUpdatedAt());
    }
}
