package com.example.registrationlogin.exception;

/**
 * Raised when a client exceeds one of the password-reset rate limits.
 *
 * <p>The message is safe to return to the API client: it never contains the identifier that
 * was rate limited, so the response cannot be used to find out which accounts exist.</p>
 */
public class TooManyRequestsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** How long the client has to wait before the limit is lifted again. */
    private final long retryAfterSeconds;

    public TooManyRequestsException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = Math.max(retryAfterSeconds, 0);
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
