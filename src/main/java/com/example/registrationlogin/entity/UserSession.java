package com.example.registrationlogin.entity;

import jakarta.persistence.*;

import java.time.LocalDateTime;

/**
 * Persistent record of an issued login session, mapped to the existing {@code sessions} table.
 *
 * <p>Each successful login writes one row. The row lets the server answer three questions
 * that a stateless JWT alone cannot:</p>
 * <ul>
 *   <li><b>Is this token still an active session?</b> - checked on every protected request.</li>
 *   <li><b>Has this session been revoked?</b> - written on logout, password change and
 *       password reset.</li>
 *   <li><b>How long was the session valid?</b> - mirrors the JWT expiry so the two cannot
 *       disagree.</li>
 * </ul>
 *
 * <p><b>No raw token is ever stored.</b> The {@code jwt_token} column is intentionally left
 * {@code null}: the {@link #tokenHash} column holds a SHA-256 fingerprint that is used for
 * lookups and cannot be reversed into a usable bearer token.</p>
 *
 * <p>The association to {@code users} is stored as the plain {@code user_id} foreign key
 * rather than a {@code @ManyToOne} association, matching the style of the other entities in
 * this project and keeping the lookups free of lazy-loading behaviour. The
 * {@code fk_sessions_user} foreign key constraint still guarantees that a session can never
 * outlive the account it belongs to.</p>
 */
@Entity
@Table(name = "sessions")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Foreign key to {@code users.id} - {@code ON DELETE CASCADE} in the schema. */
    @Column(name = "user_id", nullable = false)
    private Long userId;

    /**
     * SHA-256 fingerprint of the issued JWT, in lowercase hexadecimal (64 characters).
     * The raw token is never persisted.
     */
    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    /**
     * Reserved column for the raw token. It is deliberately never populated - see the class
     * documentation. The {@link #tokenHash} column is what the application uses.
     */
    @Column(name = "jwt_token", length = 512)
    private String jwtToken;

    /** Moment the session was created by a successful login. */
    @Column(name = "login_time", nullable = false)
    private LocalDateTime loginTime;

    /** Moment the session stops being valid - mirrors the JWT expiry. */
    @Column(name = "expiry_time", nullable = false)
    private LocalDateTime expiryTime;

    /** {@code true} once the session has been revoked by logout, password change or reset. */
    @Column(name = "is_revoked")
    private Boolean isRevoked = false;

    /** Moment the session was revoked, {@code null} while the session is active. */
    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    public UserSession() {
    }

    public UserSession(Long userId, String tokenHash, LocalDateTime loginTime, LocalDateTime expiryTime) {
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.loginTime = loginTime;
        this.expiryTime = expiryTime;
        this.isRevoked = false;
    }

    @PrePersist
    protected void onCreate() {
        if (this.loginTime == null) {
            this.loginTime = LocalDateTime.now();
        }
        if (this.isRevoked == null) {
            this.isRevoked = false;
        }
    }

    /**
     * Marks this session as revoked, stamping the moment of revocation.
     */
    public void revoke() {
        this.isRevoked = true;
        this.revokedAt = LocalDateTime.now();
    }

    /**
     * Tells whether this session is currently usable, i.e. it has not been revoked and its
     * expiry time is still in the future.
     */
    public boolean isActiveAt(LocalDateTime moment) {
        return !Boolean.TRUE.equals(this.isRevoked)
                && this.expiryTime != null
                && this.expiryTime.isAfter(moment);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public String getJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }

    public LocalDateTime getExpiryTime() {
        return expiryTime;
    }

    public void setExpiryTime(LocalDateTime expiryTime) {
        this.expiryTime = expiryTime;
    }

    public Boolean getIsRevoked() {
        return isRevoked;
    }

    public void setIsRevoked(Boolean isRevoked) {
        this.isRevoked = isRevoked;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }
}
