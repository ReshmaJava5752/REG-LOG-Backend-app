package com.example.registrationlogin.controller;

import com.example.registrationlogin.dto.*;
import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.exception.TooManyRequestsException;
import com.example.registrationlogin.service.OtpRateLimiter;
import com.example.registrationlogin.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping({"/api/auth", "/api", ""})
public class AuthController {

    private final UserService userService;
    private final OtpRateLimiter otpRateLimiter;

    @Autowired
    public AuthController(UserService userService, OtpRateLimiter otpRateLimiter) {
        this.userService = userService;
        this.otpRateLimiter = otpRateLimiter;
    }

    /**
     * Health check endpoint to confirm backend is running.
     */
    @GetMapping("/status")
    public ResponseEntity<ApiResponse> getStatus() {
        return ResponseEntity.ok(new ApiResponse(true, "Backend service is up and running."));
    }

    /**
     * User registration endpoint (supports /register, /reg, /api/reg, /api/register, /api/auth/register).
     */
    @PostMapping({"/register", "/reg"})
    public ResponseEntity<ApiResponse> registerUser(@Valid @RequestBody RegisterRequest request) {
        UserResponse createdUser = userService.registerUser(request);
        return new ResponseEntity<>(
                new ApiResponse(true, "Registration successful! You can now log in.", createdUser),
                HttpStatus.CREATED
        );
    }

    /**
     * User login authentication endpoint (accepts email or mobile number).
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse> loginUser(@Valid @RequestBody LoginRequest request) {
        AuthResponse authResponse = userService.authenticateUser(request);
        return ResponseEntity.ok(
                new ApiResponse(true, "Login successful!", authResponse)
        );
    }

    /**
     * User logout endpoint with token revocation.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logoutUser(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7).trim();
            userService.logout(token);
        }
        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully."));
    }

    /**
     * Forgot password endpoint requesting OTP.
     *
     * <p>The response is the same generic message whether or not the account exists, so the
     * endpoint cannot be used to discover registered users. A per-account limit and a
     * per-client limit protect the mailbox and the endpoint itself; both are answered with
     * HTTP 429 Too Many Requests.</p>
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                                      HttpServletRequest httpRequest) {
        enforceClientRateLimit(httpRequest);
        userService.forgotPassword(request);
        return ResponseEntity.ok(
                new ApiResponse(true, "If an account matches the provided email or mobile number, a verification OTP has been generated.")
        );
    }

    /**
     * Verify OTP endpoint returning single-use reset token.
     */
    @PostMapping("/verify-otp")
    public ResponseEntity<ApiResponse> verifyOtp(@Valid @RequestBody VerifyOtpRequest request,
                                                  HttpServletRequest httpRequest) {
        enforceClientRateLimit(httpRequest);
        String resetToken = userService.verifyOtp(request);
        return ResponseEntity.ok(
                new ApiResponse(true, "OTP verified successfully. You may now reset your password.", Map.of("resetToken", resetToken))
        );
    }

    /**
     * Limits how often a single client may call the password-recovery endpoints.
     *
     * <p>The remote address of the connection is used as the key. Forwarded headers are
     * deliberately ignored because a client can set them freely, which would let an attacker
     * sidestep the limit. In front of a reverse proxy every client shares one address, so the
     * limit then applies to the proxy - raise it or move the check behind the proxy in that
     * setup.</p>
     */
    private void enforceClientRateLimit(HttpServletRequest httpRequest) {
        if (httpRequest == null) {
            return;
        }

        String clientAddress = httpRequest.getRemoteAddr();
        if (!StringUtils.hasText(clientAddress)) {
            return;
        }

        if (!otpRateLimiter.tryAcquire(OtpRateLimiter.SCOPE_CLIENT, clientAddress)) {
            throw new TooManyRequestsException(
                    "Too many password recovery requests from this client. Please try again later.",
                    otpRateLimiter.retryAfterSeconds(OtpRateLimiter.SCOPE_CLIENT, clientAddress));
        }
    }

    /**
     * Reset password endpoint using verified reset token.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        userService.resetPassword(request);
        return ResponseEntity.ok(
                new ApiResponse(true, "Password has been reset successfully. Please log in with your new password.")
        );
    }

    /**
     * Change password endpoint for authenticated users.
     */
    @PutMapping("/change-password")
    public ResponseEntity<ApiResponse> changePassword(Authentication authentication,
                                                      @Valid @RequestBody ChangePasswordRequest request) {
        String identifier = null;
        if (authentication != null && authentication.getPrincipal() instanceof User user) {
            identifier = user.getEmail();
        } else if (authentication != null) {
            identifier = authentication.getName();
        }

        if (identifier == null || identifier.isBlank()) {
            return new ResponseEntity<>(
                    new ApiResponse(false, "Authentication required to change password."),
                    HttpStatus.UNAUTHORIZED
            );
        }

        userService.changePassword(identifier, request);
        return ResponseEntity.ok(
                new ApiResponse(true, "Password changed successfully. Please log in again with your new password.")
        );
    }

    /**
     * Get user profile (Protected endpoint, read from the authenticated principal).
     *
     * <p>The profile is always taken from the authenticated user. An earlier version also
     * accepted an {@code ?email=} query parameter as a fallback, which was unreachable while
     * the route required authentication but would have become an identifier-oracle as soon as
     * that changed - so the fallback has been removed.</p>
     */
    @GetMapping("/profile")
    public ResponseEntity<ApiResponse> getUserProfile(Authentication authentication) {
        String lookupIdentifier = null;

        if (authentication != null && authentication.getPrincipal() instanceof User user) {
            lookupIdentifier = user.getEmail();
        } else if (authentication != null) {
            lookupIdentifier = authentication.getName();
        }

        if (lookupIdentifier == null || lookupIdentifier.isBlank()) {
            return new ResponseEntity<>(
                    new ApiResponse(false, "User identifier is required."),
                    HttpStatus.BAD_REQUEST
            );
        }

        UserResponse user = userService.getUserByIdentifier(lookupIdentifier);
        return ResponseEntity.ok(new ApiResponse(true, "User profile retrieved.", user));
    }
}
