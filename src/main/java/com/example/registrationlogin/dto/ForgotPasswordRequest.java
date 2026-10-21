package com.example.registrationlogin.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ForgotPasswordRequest {

    @NotBlank(message = "Email or mobile number is required")
    @Size(max = 150, message = "Email or mobile number cannot exceed 150 characters")
    private String identifier;

    public ForgotPasswordRequest() {
    }

    public ForgotPasswordRequest(String identifier) {
        this.identifier = identifier;
    }

    public String getIdentifier() {
        return identifier != null ? identifier.trim() : null;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }
}
