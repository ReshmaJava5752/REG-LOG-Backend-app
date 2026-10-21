package com.example.registrationlogin.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class VerifyOtpRequest {

    @NotBlank(message = "Email or mobile number is required")
    @Size(max = 150, message = "Email or mobile number cannot exceed 150 characters")
    private String identifier;

    @NotBlank(message = "OTP code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "OTP code must be exactly 6 digits")
    private String otpCode;

    public VerifyOtpRequest() {
    }

    public VerifyOtpRequest(String identifier, String otpCode) {
        this.identifier = identifier;
        this.otpCode = otpCode;
    }

    public String getIdentifier() {
        return identifier != null ? identifier.trim() : null;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getOtpCode() {
        return otpCode != null ? otpCode.trim() : null;
    }

    public void setOtpCode(String otpCode) {
        this.otpCode = otpCode;
    }
}
