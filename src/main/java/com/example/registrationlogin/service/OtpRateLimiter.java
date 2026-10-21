package com.example.registrationlogin.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiter for the password-recovery endpoints.
 *
 * <p>Three independent scopes are enforced:</p>
 * <ul>
 *   <li>{@link #SCOPE_REQUEST} - how often a single account may ask for a new OTP. This
 *       protects the mailbox from being flooded and stops an attacker from burning through the
 *       three verification attempts of a genuine code.</li>
 *   <li>{@link #SCOPE_VERIFY} - how often a single account may submit a verification attempt.
 *       This complements the per-code attempt limit and blunts a brute force that requests a
 *       fresh code for every guess.</li>
 *   <li>{@link #SCOPE_CLIENT} - how often a single client may call the recovery endpoints.
 *       This blunts account enumeration, in which one attacker walks through many
 *       identifiers.</li>
 * </ul>
 *
 * <h2>Anti-enumeration</h2>
 * <p>The limiter counts an attempt <em>before</em> the account is looked at, and it counts it
 * whether or not the account exists. An identifier therefore behaves exactly the same way when
 * it belongs to nobody, so the endpoint cannot be used to discover which accounts are
 * registered.</p>
 *
 * <h2>Window</h2>
 * <p>A fixed window is used: the first attempt opens a window and every further attempt inside
 * that window counts against the limit. The window restarts once it has elapsed. Counters are
 * kept in memory, so they are reset when the backend restarts - see the limitations section of
 * the README.</p>
 */
@Service
public class OtpRateLimiter {

    /** Scope for {@code POST /forgot-password}, keyed by the account. */
    public static final String SCOPE_REQUEST = "otp-request";

    /** Scope for {@code POST /verify-otp}, keyed by the account. */
    public static final String SCOPE_VERIFY = "otp-verify";

    /** Scope for the recovery endpoints as a whole, keyed by the client address. */
    public static final String SCOPE_CLIENT = "otp-client";

    /** Maximum number of OTP requests per account and window. */
    @Value("${app.otp.rate-limit.request.max-per-window:5}")
    private int requestMaxPerWindow = 5;

    /** Length of the OTP request window in minutes. */
    @Value("${app.otp.rate-limit.request.window-minutes:15}")
    private long requestWindowMinutes = 15;

    /** Maximum number of verification attempts per account and window. */
    @Value("${app.otp.rate-limit.verify.max-per-window:10}")
    private int verifyMaxPerWindow = 10;

    /** Length of the verification window in minutes. */
    @Value("${app.otp.rate-limit.verify.window-minutes:15}")
    private long verifyWindowMinutes = 15;

    /** Maximum number of recovery calls per client address and window. */
    @Value("${app.otp.rate-limit.client.max-per-window:30}")
    private int clientMaxPerWindow = 30;

    /** Length of the client window in minutes. */
    @Value("${app.otp.rate-limit.client.window-minutes:15}")
    private long clientWindowMinutes = 15;

    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    /** A counting window for one key. */
    private static final class Window {
        private final long startedAtMs;
        private int count;

        private Window(long startedAtMs, int count) {
            this.startedAtMs = startedAtMs;
            this.count = count;
        }
    }

    /**
     * Counts one attempt and reports whether the attempt is allowed.
     *
     * <p>An attempt that is rejected still counts, so a client that keeps hammering the endpoint
     * stays blocked until the window has elapsed.</p>
     *
     * @param scope one of {@link #SCOPE_REQUEST}, {@link #SCOPE_VERIFY}, {@link #SCOPE_CLIENT}
     * @param key   the account identifier or client address the attempt belongs to
     * @return {@code true} when the attempt is within the limit
     */
    public boolean tryAcquire(String scope, String key) {
        if (scope == null || key == null) {
            return true;
        }

        String normalisedKey = normalise(key);
        if (normalisedKey.isEmpty()) {
            return true;
        }

        int max = maxFor(scope);
        long windowMs = windowMillisFor(scope);
        if (max <= 0 || windowMs <= 0) {
            // The limit is disabled by configuration.
            return true;
        }

        purgeExpiredWindows(windowMs);

        long now = nowMs();
        String compositeKey = scope + '|' + normalisedKey;

        Window window = windows.compute(compositeKey, (k, existing) -> {
            if (existing == null || now - existing.startedAtMs >= windowMs) {
                return new Window(now, 1);
            }
            existing.count++;
            return existing;
        });

        return window.count <= max;
    }

    /**
     * Tells how long the client has to wait until the limit for the given key is lifted.
     *
     * @return the number of seconds to wait, {@code 0} when the key is not rate limited
     */
    public long retryAfterSeconds(String scope, String key) {
        if (scope == null || key == null) {
            return 0L;
        }

        Window window = windows.get(scope + '|' + normalise(key));
        if (window == null) {
            return 0L;
        }

        long remaining = window.startedAtMs + windowMillisFor(scope) - nowMs();
        return remaining <= 0 ? 0L : (remaining + 999L) / 1000L;
    }

    /**
     * Removes all counters. Used by the tests.
     */
    public void reset() {
        windows.clear();
    }

    /**
     * Returns the number of attempts currently counted for the given key.
     */
    public int countFor(String scope, String key) {
        Window window = windows.get(scope + '|' + normalise(key));
        return window == null ? 0 : window.count;
    }

    /**
     * The current time in milliseconds. Overridable so that the window behaviour can be
     * tested deterministically instead of by waiting.
     */
    protected long nowMs() {
        return System.currentTimeMillis();
    }

    public void setRequestMaxPerWindow(int requestMaxPerWindow) {
        this.requestMaxPerWindow = requestMaxPerWindow;
    }

    public void setRequestWindowMinutes(long requestWindowMinutes) {
        this.requestWindowMinutes = requestWindowMinutes;
    }

    public void setVerifyMaxPerWindow(int verifyMaxPerWindow) {
        this.verifyMaxPerWindow = verifyMaxPerWindow;
    }

    public void setVerifyWindowMinutes(long verifyWindowMinutes) {
        this.verifyWindowMinutes = verifyWindowMinutes;
    }

    public void setClientMaxPerWindow(int clientMaxPerWindow) {
        this.clientMaxPerWindow = clientMaxPerWindow;
    }

    public void setClientWindowMinutes(long clientWindowMinutes) {
        this.clientWindowMinutes = clientWindowMinutes;
    }

    private int maxFor(String scope) {
        return switch (scope) {
            case SCOPE_REQUEST -> requestMaxPerWindow;
            case SCOPE_VERIFY -> verifyMaxPerWindow;
            case SCOPE_CLIENT -> clientMaxPerWindow;
            default -> 0;
        };
    }

    private long windowMillisFor(String scope) {
        long minutes = switch (scope) {
            case SCOPE_REQUEST -> requestWindowMinutes;
            case SCOPE_VERIFY -> verifyWindowMinutes;
            case SCOPE_CLIENT -> clientWindowMinutes;
            default -> 0L;
        };
        return minutes * 60_000L;
    }

    /**
     * Normalises a key so that the same account cannot bypass a limit by changing the case or
     * adding whitespace.
     */
    private String normalise(String key) {
        return key == null ? "" : key.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * Drops windows that have elapsed, so the map cannot grow without bound.
     */
    private void purgeExpiredWindows(long windowMs) {
        if (windows.size() < 1000) {
            return;
        }
        long now = nowMs();
        windows.entrySet().removeIf(entry -> now - entry.getValue().startedAtMs >= windowMs);
    }
}
