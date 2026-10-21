package com.example.registrationlogin;

import com.example.registrationlogin.exception.EmailDeliveryException;
import com.example.registrationlogin.service.EmailService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Unit tests for the SMTP e-mail delivery used by the password-reset OTP flow.
 * These assert that credentials and SMTP internals never leak into the
 * exception that can reach an API client.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    private EmailService emailService;

    @BeforeEach
    void setUp() {
        emailService = new EmailService(mailSender, "sender@gmail.com", "smtp");
    }

    @Test
    @DisplayName("Should send the OTP e-mail with the configured sender and recipient")
    void sendOtpEmail_Success() {
        emailService.sendOtpEmail("john@example.com", "123456", 5);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should wrap a mail send failure in a sanitized EmailDeliveryException")
    void sendOtpEmail_MailFailure_ThrowsSanitizedException() {
        doThrow(new MailSendException("535 5.7.8 Username and Password not accepted for user 'sender@gmail.com'"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        EmailDeliveryException exception = assertThrows(EmailDeliveryException.class, () ->
                emailService.sendOtpEmail("john@example.com", "123456", 5));

        assertEquals("SMTP_SEND_FAILED", exception.getReason());
        assertEquals("Email delivery is temporarily unavailable. Please try again later.", exception.getMessage());
    }

    @Test
    @DisplayName("Should not leak SMTP credentials or the OTP through the exception message")
    void sendOtpEmail_MailFailure_DoesNotLeakSecrets() {
        doThrow(new MailAuthenticationException("535-5.7.8 Bad credentials for secret-app-password"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        EmailDeliveryException exception = assertThrows(EmailDeliveryException.class, () ->
                emailService.sendOtpEmail("john@example.com", "123456", 5));

        String message = exception.getMessage();
        assertTrue(!message.contains("123456"), "Exception message must not contain the OTP");
        assertTrue(!message.contains("secret-app-password"), "Exception message must not contain credentials");
        assertTrue(!message.contains("sender@gmail.com"), "Exception message must not contain the SMTP account");
    }

    @Test
    @DisplayName("Should print the OTP to the log instead of sending mail in console mode")
    void sendOtpEmail_ConsoleMode_DoesNotUseSmtp() {
        EmailService consoleService = new EmailService(mailSender, "sender@gmail.com", "console");

        consoleService.sendOtpEmail("john@example.com", "123456", 5);

        verify(mailSender, never()).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should fall back to SMTP delivery for an unknown delivery mode")
    void sendOtpEmail_UnknownMode_FallsBackToSmtp() {
        EmailService unknownModeService = new EmailService(mailSender, "sender@gmail.com", "carrier-pigeon");

        unknownModeService.sendOtpEmail("john@example.com", "123456", 5);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should treat a null delivery mode as SMTP")
    void sendOtpEmail_NullMode_TreatsAsSmtp() {
        EmailService nullModeService = new EmailService(mailSender, "sender@gmail.com", null);

        nullModeService.sendOtpEmail("john@example.com", "123456", 5);

        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should report a sanitized failure when the mail sender rejects the message")
    void sendOtpEmail_GenericMailException_ThrowsSanitizedException() {
        doThrow(new MailSendException("Connection refused to smtp.gmail.com:587"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        EmailDeliveryException exception = assertThrows(EmailDeliveryException.class, () ->
                emailService.sendOtpEmail("john@example.com", "123456", 5));

        assertEquals("SMTP_SEND_FAILED", exception.getReason());
        assertEquals("Email delivery is temporarily unavailable. Please try again later.", exception.getMessage());
    }
}
