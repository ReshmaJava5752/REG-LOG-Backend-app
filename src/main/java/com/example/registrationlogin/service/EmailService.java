package com.example.registrationlogin.service;

import com.example.registrationlogin.exception.EmailDeliveryException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * Sends password-reset OTP codes via SMTP e-mail.
 *
 * <p>Every connection detail and credential is supplied through Spring Boot properties that read
 * them from environment variables (or the optional {@code .env} file). No credential value is
 * hard-coded here, written to the log, or carried inside an exception message that reaches the
 * API client.</p>
 *
 * <p>Delivery mode is controlled by {@code app.otp.delivery-mode}:</p>
 * <ul>
 *   <li>{@code smtp} (default) - delivers the OTP over Gmail SMTP with STARTTLS on port 587.</li>
 *   <li>{@code console} - development helper that prints the OTP to the server log instead of
 *       sending an e-mail. Never use this mode outside local development.</li>
 * </ul>
 */
@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    /** Delivery mode that sends the OTP over SMTP. */
    private static final String MODE_SMTP = "smtp";

    /** Development-only delivery mode that prints the OTP to the server log. */
    private static final String MODE_CONSOLE = "console";

    private final JavaMailSender mailSender;
    private final String fromAddress;
    private final String deliveryMode;
    private final boolean consoleLoggingAllowed;

    /**
     * Convenience constructor kept for direct (non-Spring) instantiation, e.g. in unit tests.
     */
    public EmailService(JavaMailSender mailSender, String fromAddress) {
        this(mailSender, fromAddress, MODE_SMTP);
    }

    /**
     * Convenience constructor kept for direct (non-Spring) instantiation, e.g. in unit tests.
     * The console mode is allowed here, because these instances are only used in tests.
     */
    public EmailService(JavaMailSender mailSender, String fromAddress, String deliveryMode) {
        this(mailSender, fromAddress, deliveryMode, true);
    }

    @Autowired
    public EmailService(JavaMailSender mailSender,
                        @Value("${spring.mail.from:}") String fromAddress,
                        @Value("${app.otp.delivery-mode:smtp}") String deliveryMode,
                        @Value("${app.otp.allow-console-logging:false}") boolean consoleLoggingAllowed) {
        this.mailSender = mailSender;
        this.fromAddress = (fromAddress == null) ? "" : fromAddress.trim();
        this.deliveryMode = (deliveryMode == null || deliveryMode.isBlank())
                ? MODE_SMTP
                : deliveryMode.trim().toLowerCase();
        this.consoleLoggingAllowed = consoleLoggingAllowed;
    }

    @PostConstruct
    void logActiveDeliveryMode() {
        if (MODE_CONSOLE.equals(deliveryMode)) {
            log.warn("OTP delivery mode is CONSOLE - one-time codes will be printed to the server log. "
                    + "Do not use this mode outside local development.");
        } else {
            log.info("OTP delivery mode is SMTP.");
        }
    }

    /**
     * Sends the 6-digit OTP code to the given email address.
     *
     * @param to            recipient email address
     * @param otpCode       6-digit OTP code
     * @param expiryMinutes OTP validity window in minutes
     * @throws EmailDeliveryException if the OTP could not be delivered. The exception message is
     *                                safe to return to an API client; the diagnostic detail stays
     *                                in the server log.
     */
    public void sendOtpEmail(String to, String otpCode, int expiryMinutes) {
        if (MODE_CONSOLE.equals(deliveryMode)) {
            if (!consoleLoggingAllowed) {
                // Writing a reset code to the log has to be switched on deliberately, so that a
                // misconfigured deployment can never leak codes into the log file.
                log.error("Console OTP delivery is not permitted (reason=CONSOLE_LOGGING_DISABLED). "
                        + "Set app.otp.allow-console-logging=true to allow it - local development only.");
                throw new EmailDeliveryException("CONSOLE_LOGGING_DISABLED",
                        "Email delivery is temporarily unavailable. Please try again later.");
            }
            log.warn("Password reset OTP for {}: {} (valid for {} minutes)", to, otpCode, expiryMinutes);
            return;
        }

        if (!MODE_SMTP.equals(deliveryMode)) {
            log.warn("Unknown OTP delivery mode '{}' - falling back to SMTP delivery.", deliveryMode);
        }

        deliverOverSmtp(to, otpCode, expiryMinutes);
    }

    private void deliverOverSmtp(String to, String otpCode, int expiryMinutes) {
        assertSmtpConfigured();

        String sender = resolveSender();
        if (!StringUtils.hasText(sender)) {
            log.error("OTP e-mail delivery is not configured (reason=SMTP_NO_SENDER). Set SMTP_FROM or SMTP_USERNAME.");
            throw new EmailDeliveryException("SMTP_NO_SENDER",
                    "Email delivery is temporarily unavailable. Please try again later.");
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(sender);
        message.setTo(to);
        message.setSubject("Your Password Reset OTP");
        message.setText(
                "Your password reset OTP is: " + otpCode + "\n" +
                "This OTP is valid for " + expiryMinutes + " minutes.\n" +
                "Please enter it on the OTP verification page to reset your password.\n" +
                "If you did not request a password reset, you can safely ignore this email."
        );

        try {
            mailSender.send(message);
        } catch (MailException ex) {
            // Only exception types are logged - never the message, because a MailSendException
            // message can embed the failed message (and therefore the OTP) or SMTP credentials.
            log.error("OTP e-mail delivery failed (reason=SMTP_SEND_FAILED, exception={}). "
                            + "Check SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD and that a "
                            + "Google App Password is being used.",
                    describeExceptionChain(ex));
            throw new EmailDeliveryException("SMTP_SEND_FAILED",
                    "Email delivery is temporarily unavailable. Please try again later.");
        }
    }

    /**
     * Fails fast with a sanitized message when the SMTP sender is not usable, so that a
     * misconfigured deployment reports a clear reason instead of an opaque mail error.
     */
    private void assertSmtpConfigured() {
        if (mailSender instanceof JavaMailSenderImpl sender) {
            boolean configured = StringUtils.hasText(sender.getHost())
                    && StringUtils.hasText(sender.getUsername())
                    && StringUtils.hasText(sender.getPassword());
            if (!configured) {
                log.error("OTP e-mail delivery is not configured (reason=SMTP_NOT_CONFIGURED). "
                        + "Set SMTP_HOST, SMTP_PORT, SMTP_USERNAME and SMTP_PASSWORD.");
                throw new EmailDeliveryException("SMTP_NOT_CONFIGURED",
                        "Email delivery is temporarily unavailable. Please try again later.");
            }
        }
    }

    private String resolveSender() {
        if (StringUtils.hasText(fromAddress)) {
            return fromAddress;
        }
        if (mailSender instanceof JavaMailSenderImpl sender && StringUtils.hasText(sender.getUsername())) {
            return sender.getUsername();
        }
        return "";
    }

    /**
     * Builds a short description of an exception chain using type names only, so no server
     * response text (which may echo account details) is written to the log.
     */
    private String describeExceptionChain(Throwable ex) {
        StringBuilder description = new StringBuilder(ex.getClass().getSimpleName());
        Throwable cause = ex.getCause();
        int depth = 0;
        while (cause != null && depth < 3) {
            description.append(" <- ").append(cause.getClass().getSimpleName());
            cause = cause.getCause();
            depth++;
        }
        return description.toString();
    }
}
