package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.*;
import com.example.registrationlogin.entity.PasswordResetOtp;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.exception.EmailDeliveryException;
import com.example.registrationlogin.exception.TooManyRequestsException;
import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import com.example.registrationlogin.repository.UserRepository;
import com.example.registrationlogin.security.JwtUtils;
import com.example.registrationlogin.security.TokenBlacklistService;
import com.example.registrationlogin.util.PasswordPolicy;
import com.example.registrationlogin.util.OtpHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserServiceImpl implements UserService {

    private static final Logger log = LoggerFactory.getLogger(UserServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordResetOtpRepository otpRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final TokenBlacklistService tokenBlacklistService;
    private final EmailService emailService;
    private final SessionService sessionService;
    private final OtpRateLimiter otpRateLimiter;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.otp.expiry-minutes:5}")
    private int otpExpiryMinutes;

    @Value("${app.otp.max-attempts:3}")
    private int otpMaxAttempts;

    /**
     * Server-side secret used to fingerprint the reset codes.
     *
     * <p>Defaults to the JWT secret, so a deployment that already sets {@code JWT_SECRET} does
     * not need anything extra. It can be given its own value with {@code OTP_HMAC_SECRET}.</p>
     */
    @Value("${app.otp.hmac-secret:" + OtpHasher.DEFAULT_SECRET + "}")
    private String otpHmacSecret = OtpHasher.DEFAULT_SECRET;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           PasswordResetOtpRepository otpRepository,
                           PasswordEncoder passwordEncoder,
                           JwtUtils jwtUtils,
                           TokenBlacklistService tokenBlacklistService,
                           EmailService emailService,
                           SessionService sessionService,
                           OtpRateLimiter otpRateLimiter) {
        this.userRepository = userRepository;
        this.otpRepository = otpRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
        this.tokenBlacklistService = tokenBlacklistService;
        this.emailService = emailService;
        this.sessionService = sessionService;
        this.otpRateLimiter = otpRateLimiter;
    }

    /**
     * Convenience constructor without a persistent session store, kept so that unit tests which
     * build this service by hand keep working unchanged. Session handling then behaves exactly
     * as it did before persistent sessions were introduced.
     */
    public UserServiceImpl(UserRepository userRepository,
                           PasswordResetOtpRepository otpRepository,
                           PasswordEncoder passwordEncoder,
                           JwtUtils jwtUtils,
                           TokenBlacklistService tokenBlacklistService,
                           EmailService emailService,
                           SessionService sessionService) {
        this(userRepository, otpRepository, passwordEncoder, jwtUtils, tokenBlacklistService,
                emailService, sessionService, new OtpRateLimiter());
    }

    /**
     * Convenience constructor without a persistent session store, kept so that unit tests which
     * build this service by hand keep working unchanged. Session handling then behaves exactly
     * as it did before persistent sessions were introduced.
     */
    public UserServiceImpl(UserRepository userRepository,
                           PasswordResetOtpRepository otpRepository,
                           PasswordEncoder passwordEncoder,
                           JwtUtils jwtUtils,
                           TokenBlacklistService tokenBlacklistService,
                           EmailService emailService) {
        this(userRepository, otpRepository, passwordEncoder, jwtUtils, tokenBlacklistService,
                emailService, SessionService.disabled(), new OtpRateLimiter());
    }

    @Override
    @Transactional
    public UserResponse registerUser(RegisterRequest request) {
        String fullName = request.getFullName() != null ? request.getFullName().trim() : "";
        String email = request.getEmail() != null ? request.getEmail().trim().toLowerCase() : "";
        String mobile = request.getMobileNumber() != null ? request.getMobileNumber().trim() : null;

        // 1. Validate full name length (3 to 100 characters)
        if (fullName.length() < 3 || fullName.length() > 100) {
            throw new IllegalArgumentException("Full name must be between 3 and 100 characters.");
        }

        // 2. Validate password match
        if (request.getPassword() == null || !request.getPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }

        // 3. Validate password complexity rules
        validatePasswordComplexity(request.getPassword());

        // 4. Validate duplicate email
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("An account with this email address already exists. Please log in.");
        }

        // 5. Validate mobile number (exactly 10 digits) and uniqueness if provided
        if (mobile != null && !mobile.isBlank()) {
            if (!mobile.matches("^[0-9]{10}$")) {
                throw new IllegalArgumentException("Mobile number must contain exactly 10 digits.");
            }
            if (userRepository.existsByMobileNumber(mobile)) {
                throw new IllegalArgumentException("An account with this mobile number already exists. Please log in.");
            }
        }

        // 6. Secure password with BCrypt
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // 7. Persist user entity
        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setMobileNumber(mobile != null && !mobile.isBlank() ? mobile : null);
        user.setPassword(hashedPassword);

        User savedUser = userRepository.save(user);

        return new UserResponse(
                savedUser.getId(),
                savedUser.getFullName(),
                savedUser.getEmail(),
                savedUser.getMobileNumber(),
                savedUser.getCreatedAt(),
                savedUser.getUpdatedAt()
        );
    }

    @Override
    @Transactional(readOnly = true)
    public AuthResponse authenticateUser(LoginRequest request) {
        String identifier = request.getIdentifier();

        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Email or mobile number is required.");
        }

        // 1. Look up user by email or mobile number
        User user = userRepository.findByEmailOrMobileNumber(identifier.toLowerCase(), identifier)
                .orElseThrow(() -> new IllegalArgumentException("Invalid email/mobile or password."));

        // 2. Compare raw password with stored BCrypt hash
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Invalid email/mobile or password.");
        }

        // 3. Generate JWT Token
        String token = jwtUtils.generateToken(user.getEmail());

        // 4. Record the session so the token can be revoked later, even across a restart.
        //    A failure here must not prevent the login, so it is logged and swallowed - the
        //    in-memory revocation list then covers the token for the lifetime of the process.
        try {
            sessionService.registerSession(user, token, jwtUtils.getExpirationDateFromToken(token));
        } catch (DataAccessException ex) {
            log.error("Could not store the login session (exception={}). The token stays valid "
                    + "until it expires; the in-memory revocation list still applies.",
                    ex.getClass().getSimpleName());
        }

        UserResponse userResponse = new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getMobileNumber(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );

        return new AuthResponse(token, userResponse);
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByEmail(String email) {
        User user = userRepository.findByEmail(email.trim().toLowerCase())
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + email));

        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getMobileNumber(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserByIdentifier(String identifier) {
        String cleanId = identifier.trim();
        User user = userRepository.findByEmailOrMobileNumber(cleanId.toLowerCase(), cleanId)
                .orElseThrow(() -> new IllegalArgumentException("User not found for identifier: " + identifier));

        return new UserResponse(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                user.getMobileNumber(),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    @Override
    @Transactional
    public void forgotPassword(ForgotPasswordRequest request) {
        String identifier = request.getIdentifier();
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Email or mobile number is required.");
        }

        Optional<User> userOptional = userRepository.findByEmailOrMobileNumber(identifier.toLowerCase(), identifier);
        User user = userOptional.orElse(null);

        // Rate limiting happens for every request, whether or not the account exists, and the
        // counter is keyed on the canonical account e-mail. An identifier therefore behaves
        // exactly the same way whether it belongs to a registered account or not, so the
        // endpoint cannot be used to enumerate users.
        String rateLimitKey = user != null ? user.getEmail() : normaliseIdentifier(identifier);
        if (!otpRateLimiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, rateLimitKey)) {
            throw new TooManyRequestsException(
                    "Too many password reset codes have been requested for this account. "
                            + "Please wait before requesting another one.",
                    otpRateLimiter.retryAfterSeconds(OtpRateLimiter.SCOPE_REQUEST, rateLimitKey));
        }

        // The identifier the code is stored under. For a known account this is the canonical
        // e-mail address, so the code is found again no matter whether the user signs in with
        // the e-mail or with the mobile number.
        String otpIdentifier = user != null ? user.getEmail() : normaliseIdentifier(identifier);

        // Invalidate any code that was requested earlier for this account/identifier.
        otpRepository.deleteByIdentifier(otpIdentifier);
        if (!otpIdentifier.equals(normaliseIdentifier(identifier))) {
            otpRepository.deleteByIdentifier(normaliseIdentifier(identifier));
        }

        // Generate secure 6-digit numeric OTP (100000 - 999999). The plain code only ever
        // exists in memory and in the e-mail - the database stores a fingerprint of it.
        int randomCode = 100000 + secureRandom.nextInt(900000);
        String otpCode = String.valueOf(randomCode);

        // One effective validity window, used for the stored expiry and for the e-mail text.
        int effectiveExpiryMinutes = otpExpiryMinutes > 0 ? otpExpiryMinutes : 5;
        LocalDateTime expiryTime = LocalDateTime.now().plusMinutes(effectiveExpiryMinutes);

        PasswordResetOtp otpRecord = new PasswordResetOtp(otpIdentifier,
                OtpHasher.hash(otpHmacSecret, otpCode), expiryTime);
        otpRepository.save(otpRecord);

        // Security requirement: Do not reveal whether an email or phone exists.
        //
        // A code record is written for unknown identifiers as well. The record is a decoy - the
        // code in it is never sent to anybody - but it makes the verification endpoint behave
        // exactly the same way for a registered and for an unregistered address, so the two
        // cannot be told apart. Without it, the answer to "is this address registered?" would
        // leak through the different messages of the verification endpoint.
        if (user != null) {
            // Send the OTP by e-mail. A delivery failure must not change the HTTP response,
            // otherwise this endpoint would reveal whether an account exists. The failure is
            // logged server-side (without SMTP internals) and the response stays generic.
            // The stored OTP is left in place: it expires on its own and is replaced by the
            // next request, and a delivery that reported an error may still have arrived.
            try {
                emailService.sendOtpEmail(user.getEmail(), otpCode, effectiveExpiryMinutes);
            } catch (EmailDeliveryException ex) {
                log.error("Password reset OTP e-mail delivery failed (reason={}).", ex.getReason());
            }
        }
    }

    /**
     * Verifies a reset code and issues a single-use reset token.
     *
     * <p>{@code noRollbackFor = IllegalArgumentException.class} is essential: a wrong code
     * raises an {@code IllegalArgumentException} <em>after</em> the attempt counter has been
     * written. With the default rollback rule the transaction would be discarded and the
     * counter would never increase, which would silently disable the limit on the number of
     * attempts. The only write in this method is that counter, so committing it is safe.</p>
     */
    @Override
    @Transactional(noRollbackFor = IllegalArgumentException.class)
    public String verifyOtp(VerifyOtpRequest request) {
        String identifier = request.getIdentifier();
        if (identifier == null || identifier.isBlank()) {
            throw new IllegalArgumentException("Email or mobile number is required.");
        }

        Optional<User> userOptional = userRepository.findByEmailOrMobileNumber(identifier.toLowerCase(), identifier);

        // Rate limiting happens before the account is resolved and counts every attempt, so an
        // unknown identifier is throttled exactly like a known one and the endpoint cannot be
        // used to enumerate users.
        String rateLimitKey = userOptional.map(User::getEmail).orElseGet(() -> identifier.trim().toLowerCase());
        if (!otpRateLimiter.tryAcquire(OtpRateLimiter.SCOPE_VERIFY, rateLimitKey)) {
            throw new TooManyRequestsException(
                    "Too many verification attempts. Please request a new code and try again later.",
                    otpRateLimiter.retryAfterSeconds(OtpRateLimiter.SCOPE_VERIFY, rateLimitKey));
        }

        User user = userOptional.orElse(null);

        // The identifier the code is stored under - the same rule as in forgotPassword, so a
        // code is found again whether the user signs in with the e-mail or the mobile number.
        String otpIdentifier = user != null ? user.getEmail() : normaliseIdentifier(identifier);

        PasswordResetOtp otp = otpRepository.findTopByIdentifierOrderByCreatedAtDesc(otpIdentifier)
                .orElseThrow(() -> new IllegalArgumentException("No active OTP request found. Please request a new OTP."));

        // Check if expired
        if (otp.getExpiryTime().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("OTP has expired. Please request a new OTP.");
        }

        // Check attempts limit (max 3)
        if (otp.getAttempts() >= (otpMaxAttempts > 0 ? otpMaxAttempts : 3)) {
            throw new IllegalArgumentException("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        // Increment attempt count
        otp.setAttempts(otp.getAttempts() + 1);

        // Check code match against the stored fingerprint. The plain code is never stored, so
        // it cannot be read back from the database.
        String submittedCode = request.getOtpCode() != null ? request.getOtpCode().trim() : "";
        if (!OtpHasher.matches(otpHmacSecret, otp.getOtpHash(), submittedCode)) {
            otpRepository.save(otp);
            int remaining = otpMaxAttempts - otp.getAttempts();
            throw new IllegalArgumentException("Invalid OTP code. " + (remaining > 0 ? remaining + " attempts remaining." : "Please request a new OTP."));
        }

        // Success: Mark verified and generate single-use reset token
        otp.setIsVerified(true);
        String resetToken = UUID.randomUUID().toString();
        otp.setResetToken(resetToken);
        otpRepository.save(otp);

        return resetToken;
    }

    @Override
    @Transactional
    public void resetPassword(ResetPasswordRequest request) {
        String identifier = request.getIdentifier();
        String resetToken = request.getResetToken();

        if (identifier == null || identifier.isBlank() || resetToken == null || resetToken.isBlank()) {
            throw new IllegalArgumentException("Identifier and reset token are required.");
        }

        // Validate password confirmation and complexity
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match.");
        }
        validatePasswordComplexity(request.getNewPassword());

        User user = userRepository.findByEmailOrMobileNumber(identifier.toLowerCase(), identifier)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired password reset session."));

        PasswordResetOtp otp = otpRepository.findByIdentifierAndResetToken(user.getEmail(), resetToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid or expired password reset session."));

        if (!Boolean.TRUE.equals(otp.getIsVerified())) {
            // The same message as for an unknown token, so that the response cannot be used
            // to find out whether a reset token exists.
            throw new IllegalArgumentException("Invalid or expired password reset session.");
        }

        // Time-limit reset token (e.g. within 15 minutes of creation)
        if (otp.getExpiryTime().plusMinutes(10).isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Password reset window has expired. Please start over.");
        }

        // Hash new password using BCrypt
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // Invalidate single-use reset token by removing the OTP record
        otpRepository.delete(otp);

        // Revoke active sessions/tokens for this user
        revokeAllSessionsOf(user);
    }

    @Override
    @Transactional
    public void changePassword(String currentIdentifier, ChangePasswordRequest request) {
        if (currentIdentifier == null || currentIdentifier.isBlank()) {
            throw new IllegalArgumentException("User authentication required.");
        }

        User user = userRepository.findByEmailOrMobileNumber(currentIdentifier.toLowerCase(), currentIdentifier)
                .orElseThrow(() -> new IllegalArgumentException("User not found."));

        // 1. Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect.");
        }

        // 2. Verify new password is not identical to current
        if (request.getCurrentPassword().equals(request.getNewPassword())) {
            throw new IllegalArgumentException("New password cannot be the same as your current password.");
        }

        // 3. Verify confirmation
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("New password and confirm password do not match.");
        }

        // 4. Validate complexity
        validatePasswordComplexity(request.getNewPassword());

        // 5. Hash new password and save
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        // 6. Invalidate active tokens
        revokeAllSessionsOf(user);
    }

    @Override
    public void logout(String token) {
        if (token != null && !token.isBlank()) {
            // Revoke the stored session first - this survives a backend restart.
            try {
                sessionService.revokeSession(token);
            } catch (DataAccessException ex) {
                log.error("Could not revoke the stored session on logout (exception={}). The "
                    + "in-memory revocation list still applies.",
                        ex.getClass().getSimpleName());
            }

            try {
                Date expiry = jwtUtils.getExpirationDateFromToken(token);
                long expiryMs = expiry != null ? expiry.getTime() : System.currentTimeMillis() + 86400000;
                tokenBlacklistService.blacklistToken(token, expiryMs);
            } catch (Exception e) {
                // If token cannot be parsed, add anyway with 24hr expiry
                tokenBlacklistService.blacklistToken(token, System.currentTimeMillis() + 86400000);
            }
        }
    }

    /**
     * Revokes every session of the given user, both in the persistent session store and in the
     * in-memory revocation list.
     *
     * <p>Used after a password change and after a password reset, so that a token issued
     * before the credentials changed cannot be used afterwards.</p>
     */
    private void revokeAllSessionsOf(User user) {
        try {
            sessionService.revokeAllSessions(user.getId());
        } catch (DataAccessException ex) {
            log.error("Could not revoke the stored sessions of the account (exception={}). The "
                    + "in-memory revocation list still applies.",
                    ex.getClass().getSimpleName());
        }
        tokenBlacklistService.revokeAllUserTokens(user.getEmail());
    }

    private void validatePasswordComplexity(String password) {
        if (!PasswordPolicy.isValid(password)) {
            throw new IllegalArgumentException(PasswordPolicy.SERVICE_MESSAGE);
        }
    }

    /**
     * Normalises an identifier so that the same address cannot be used twice under different
     * spellings - for example {@code User@Example.com} and {@code user@example.com}. The
     * normal form is also what a code record is stored under when the address belongs to
     * nobody, so that the verification endpoint treats both spellings the same way.
     */
    private String normaliseIdentifier(String identifier) {
        return identifier == null ? "" : identifier.trim().toLowerCase(java.util.Locale.ROOT);
    }
}
