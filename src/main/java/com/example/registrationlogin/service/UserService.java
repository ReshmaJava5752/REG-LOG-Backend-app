package com.example.registrationlogin.service;

import com.example.registrationlogin.dto.*;

public interface UserService {

    UserResponse registerUser(RegisterRequest request);

    AuthResponse authenticateUser(LoginRequest request);

    UserResponse getUserByEmail(String email);

    UserResponse getUserByIdentifier(String identifier);

    void forgotPassword(ForgotPasswordRequest request);

    String verifyOtp(VerifyOtpRequest request);

    void resetPassword(ResetPasswordRequest request);

    void changePassword(String currentIdentifier, ChangePasswordRequest request);

    void logout(String token);
}
