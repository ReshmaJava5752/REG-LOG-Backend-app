package com.example.registrationlogin.util;

import java.util.regex.Pattern;

/**
 * Single source of truth for the password complexity policy.
 *
 * <p>The rule was previously duplicated in {@code UserServiceImpl} (runtime validation) and in the
 * {@code @Pattern} annotations of {@code RegisterRequest}, {@code ResetPasswordRequest} and
 * {@code ChangePasswordRequest} (bean validation). Duplicated rules drift apart over time, so the
 * regular expression and the two user-facing messages now live here and are referenced from every
 * call site.</p>
 *
 * <p>The message texts are intentionally unchanged from the previous implementation so that the
 * existing API contract and automated tests remain valid.</p>
 */
public final class PasswordPolicy {

    /** Minimum number of characters a password must contain. */
    public static final int MIN_LENGTH = 8;

    /** The set of characters accepted as the "special character" of the policy. */
    public static final String SPECIAL_CHARACTERS = "@$!%*?&#";

    /**
     * The password complexity regular expression, as a compile-time constant so that it can be
     * referenced directly from a {@code @Pattern} annotation.
     *
     * <p>Requires at least 8 characters, including one uppercase letter, one lowercase letter, one
     * digit and one special character.</p>
     */
    public static final String REGEX =
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#])[A-Za-z\\d@$!%*?&#]{8,}$";

    /**
     * Compiled form of {@link #REGEX} for runtime validation.
     */
    public static final Pattern PATTERN = Pattern.compile(REGEX);

    /**
     * Message returned by the service layer when a password does not satisfy the policy.
     * Kept byte-identical to the previous hard-coded message.
     */
    public static final String SERVICE_MESSAGE =
            "Password must be at least 8 characters long and contain at least one uppercase letter, "
                    + "one lowercase letter, one digit, and one special character (@$!%*?&#).";

    /**
     * Message used by the bean-validation annotations on the request DTOs.
     * Kept byte-identical to the previous hard-coded message.
     */
    public static final String VALIDATION_MESSAGE =
            "Password must be at least 8 characters long and contain at least one uppercase letter, "
                    + "one lowercase letter, one digit, and one special character";

    private PasswordPolicy() {
        // Utility class - not instantiable.
    }

    /**
     * Checks whether the given password satisfies the complexity policy.
     *
     * @param password the raw password to test (may be {@code null})
     * @return {@code true} when the password is compliant
     */
    public static boolean isValid(String password) {
        return password != null && PATTERN.matcher(password).matches();
    }
}
