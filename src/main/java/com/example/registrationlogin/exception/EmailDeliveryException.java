package com.example.registrationlogin.exception;

/**
 * Raised when a password-reset OTP e-mail could not be delivered.
 *
 * <p>The exception message is intentionally generic so that SMTP server responses, usernames or
 * credentials are never propagated to API clients. Operational details (reason code and the
 * exception type chain) are written to the server log instead, still without any credential
 * values.</p>
 */
public class EmailDeliveryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Short, non-sensitive diagnostic code, e.g. {@code SMTP_NOT_CONFIGURED}. */
    private final String reason;

    public EmailDeliveryException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public String getReason() {
        return reason;
    }
}
