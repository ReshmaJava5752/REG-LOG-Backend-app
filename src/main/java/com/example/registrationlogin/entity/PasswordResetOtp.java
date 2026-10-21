package com.example.registrationlogin.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "password_reset_otps")
public class PasswordResetOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "identifier", nullable = false, length = 150)
    private String identifier;

    /**
     * Fingerprint of the issued reset code, stored in the {@code otp_code} column.
     *
     * <p>The column keeps its historic name, but it no longer holds the code itself - it holds
     * an HMAC-SHA256 fingerprint that cannot be reversed and cannot be brute forced without
     * the server-side secret. See {@code OtpHasher}.</p>
     */
    @Column(name = "otp_code", nullable = false, length = 64)
    private String otpHash;

    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    @Column(name = "is_verified")
    private Boolean isVerified = false;

    @Column(name = "reset_token", length = 255)
    private String resetToken;

    @Column(name = "attempts")
    private Integer attempts = 0;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    public PasswordResetOtp() {
    }

    public PasswordResetOtp(String identifier, String otpHash, LocalDateTime expiryTime) {
        this.identifier = identifier;
        this.otpHash = otpHash;
        this.expiryTime = expiryTime;
        this.isVerified = false;
        this.attempts = 0;
    }

    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        if (this.isVerified == null) {
            this.isVerified = false;
        }
        if (this.attempts == null) {
            this.attempts = 0;
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getOtpHash() {
        return otpHash;
    }

    public void setOtpHash(String otpHash) {
        this.otpHash = otpHash;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public Boolean getIsVerified() {
        return isVerified;
    }

    public void setIsVerified(Boolean isVerified) {
        this.isVerified = isVerified;
    }

    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String resetToken) {
        this.resetToken = resetToken;
    }

    public Integer getAttempts() {
        return attempts;
    }

    public void setAttempts(Integer attempts) {
        this.attempts = attempts;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}
