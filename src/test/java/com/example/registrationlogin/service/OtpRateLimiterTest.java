package com.example.registrationlogin.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the OTP rate limiter.
 *
 * <p>The clock is overridden so that the window behaviour is verified deterministically
 * instead of by waiting for real time to pass.</p>
 */
class OtpRateLimiterTest {

    /** Limiter with a controllable clock. */
    private static class TestableOtpRateLimiter extends OtpRateLimiter {
        private long now = 1_000_000L;

        @Override
        protected long nowMs() {
            return now;
        }

        private void advanceMinutes(long minutes) {
            now += minutes * 60_000L;
        }
    }

    private TestableOtpRateLimiter limiter;

    @BeforeEach
    void setUp() {
        limiter = new TestableOtpRateLimiter();
        limiter.setRequestMaxPerWindow(3);
        limiter.setRequestWindowMinutes(15);
        limiter.setVerifyMaxPerWindow(5);
        limiter.setVerifyWindowMinutes(15);
        limiter.setClientMaxPerWindow(4);
        limiter.setClientWindowMinutes(15);
    }

    @Test
    @DisplayName("Should allow attempts up to the limit and reject the next one")
    void tryAcquire_AllowsUpToTheLimit() {
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertFalse(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"),
                "The fourth attempt must be rejected");
    }

    @Test
    @DisplayName("Should keep counting rejected attempts so hammering stays blocked")
    void tryAcquire_CountsRejectedAttempts() {
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com");
        }

        assertFalse(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertFalse(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertEquals(5, limiter.countFor(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
    }

    @Test
    @DisplayName("Should allow requests again once the window has elapsed")
    void tryAcquire_AllowsAgainAfterTheWindow() {
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com");
        }
        assertFalse(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));

        limiter.advanceMinutes(16);

        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"),
                "The limit must be lifted once the window has passed");
    }

    @Test
    @DisplayName("Should treat identifiers that differ only in case or whitespace as one key")
    void tryAcquire_NormalisesTheKey() {
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "User@Example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "  user@example.com  "));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "USER@EXAMPLE.COM"));
        assertFalse(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"),
                "Changing the case must not bypass the limit");
    }

    @Test
    @DisplayName("Should count each scope separately")
    void tryAcquire_KeepsScopesIndependent() {
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_VERIFY, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_CLIENT, "user@example.com"));
    }

    @Test
    @DisplayName("Should not share a counter between different keys")
    void tryAcquire_CountsDifferentKeysSeparately() {
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "one@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "two@example.com"));
        assertEquals(1, limiter.countFor(OtpRateLimiter.SCOPE_REQUEST, "one@example.com"));
        assertEquals(1, limiter.countFor(OtpRateLimiter.SCOPE_REQUEST, "two@example.com"));
    }

    @Test
    @DisplayName("Should report how long the client has to wait")
    void retryAfterSeconds_ReportsTheRemainingWindow() {
        limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com");

        long retryAfter = limiter.retryAfterSeconds(OtpRateLimiter.SCOPE_REQUEST, "user@example.com");

        assertTrue(retryAfter > 0, "A limited key must report a wait time");
        assertTrue(retryAfter <= 15 * 60, "The wait time must not exceed the window length");
    }

    @Test
    @DisplayName("Should report no wait time for a key that was never used")
    void retryAfterSeconds_ReturnsZeroForUnknownKey() {
        assertEquals(0L, limiter.retryAfterSeconds(OtpRateLimiter.SCOPE_REQUEST, "nobody@example.com"));
    }

    @Test
    @DisplayName("Should allow everything when the limit is switched off")
    void tryAcquire_AllowsEverythingWhenDisabled() {
        limiter.setRequestMaxPerWindow(0);

        for (int i = 0; i < 50; i++) {
            assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        }
    }

    @Test
    @DisplayName("Should ignore a missing scope or key")
    void tryAcquire_IgnoresMissingInput() {
        assertTrue(limiter.tryAcquire(null, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, null));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "   "));
    }

    @Test
    @DisplayName("Should clear every counter on reset")
    void reset_ClearsCounters() {
        for (int i = 0; i < 3; i++) {
            limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com");
        }

        limiter.reset();

        assertEquals(0, limiter.countFor(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
        assertTrue(limiter.tryAcquire(OtpRateLimiter.SCOPE_REQUEST, "user@example.com"));
    }
}
