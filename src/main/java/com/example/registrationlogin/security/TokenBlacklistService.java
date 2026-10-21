package com.example.registrationlogin.security;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlacklistService {

    // Map storing blacklisted token and its expiration timestamp
    private final Map<String, Long> blacklistedTokens = new ConcurrentHashMap<>();

    // Map storing user identifier and timestamp of last forced logout (e.g. password reset/change)
    private final Map<String, Long> userRevocationTimestamps = new ConcurrentHashMap<>();

    public void blacklistToken(String token, long expirationTimeMs) {
        if (token != null && !token.isBlank()) {
            cleanExpiredTokens();
            blacklistedTokens.put(token.trim(), expirationTimeMs);
        }
    }

    public boolean isBlacklisted(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        Long expiry = blacklistedTokens.get(token.trim());
        if (expiry == null) {
            return false;
        }
        if (System.currentTimeMillis() > expiry) {
            blacklistedTokens.remove(token.trim());
            return false;
        }
        return true;
    }

    public void revokeAllUserTokens(String identifier) {
        if (identifier != null && !identifier.isBlank()) {
            userRevocationTimestamps.put(identifier.trim().toLowerCase(), System.currentTimeMillis());
        }
    }

    /**
     * Tells whether a token was issued before the account-wide revocation.
     *
     * <p>The {@code iat} claim of a JWT only carries second precision, while the revocation is
     * stamped in milliseconds. A token that was issued in the same second as the revocation
     * therefore cannot be told apart from one that was issued before it. The whole second is
     * treated as "not before" the revocation, so that a token which was handed out
     * immediately after a password change is not rejected straight away.</p>
     *
     * <p>For every token that was issued after the session feature was introduced the exact
     * decision is made by the persistent session store; this method is the fallback for the
     * tokens that predate it.</p>
     */
    public boolean isUserTokenRevokedBefore(String identifier, long tokenIssuedAtMs) {
        if (identifier == null) {
            return false;
        }
        Long revocationTime = userRevocationTimestamps.get(identifier.trim().toLowerCase());
        if (revocationTime == null) {
            return false;
        }
        // End of the second the token was issued in. The issued-at claim of a JWT only carries
        // second precision, so the whole second is looked at.
        long endOfTokenSecond = (tokenIssuedAtMs / 1000L) * 1000L + 999L;
        return endOfTokenSecond < revocationTime;
    }

    private void cleanExpiredTokens() {
        long now = System.currentTimeMillis();
        blacklistedTokens.entrySet().removeIf(entry -> entry.getValue() < now);
    }
}
