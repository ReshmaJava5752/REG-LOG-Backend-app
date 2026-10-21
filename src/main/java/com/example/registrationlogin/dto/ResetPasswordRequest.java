package com.example.registrationlogin.dto;

import com.example.registrationlogin.util.PasswordPolicy;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class ResetPasswordRequest {

    @NotBlank(message = "Email or mobile number is required")
    @Size(max = 150, message = "Email or mobile number cannot exceed 150 characters")
    private String identifier;

    @NotBlank(message = "Reset token is required")
    private String resetToken;

    @NotBlank(message = "New password is required")
    @Pattern(
        regexp = PasswordPolicy.REGEX,
        message = PasswordPolicy.VALIDATION_MESSAGE
    )
    private String newPassword;

    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;

    public ResetPasswordRequest() {
    }

    public ResetPasswordRequest(String identifier, String resetToken, String newPassword, String confirmPassword) {
        this.identifier = identifier;
        this.resetToken = resetToken;
        this.newPassword = newPassword;
        this.confirmPassword = confirmPassword;
    }

    public String getIdentifier() {
        return identifier != null ? identifier.trim() : null;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getResetToken() {
        return resetToken != null ? resetToken.trim() : null;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}
