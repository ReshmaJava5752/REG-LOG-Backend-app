package com.example.registrationlogin.service;

import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.dao.DataAccessResourceFailureException;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for the clean-up of password reset code records.
 *
 * <p>A record must survive long enough for its reset token to still be redeemable, so the
 * cut-off has to be in the past - never the expiry time itself.</p>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpCleanupServiceTest {

    @Mock
    private PasswordResetOtpRepository otpRepository;

    private OtpCleanupService cleanupService;

    @BeforeEach
    void setUp() {
        cleanupService = new OtpCleanupService(otpRepository);
    }

    @Test
    @DisplayName("Should remove records that expired long enough ago")
    void purgeExpiredOtpRecords_RemovesOldRecords() {
        when(otpRepository.deleteByExpiryTimeBefore(any(LocalDateTime.class))).thenReturn(7L);

        cleanupService.purgeExpiredOtpRecords();

        verify(otpRepository, times(1)).deleteByExpiryTimeBefore(any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should keep records whose reset token could still be redeemed")
    void purgeExpiredOtpRecords_UsesACutOffInThePast() {
        when(otpRepository.deleteByExpiryTimeBefore(any(LocalDateTime.class))).thenReturn(0L);

        cleanupService.purgeExpiredOtpRecords();

        ArgumentCaptor<LocalDateTime> captor = ArgumentCaptor.forClass(LocalDateTime.class);
        verify(otpRepository).deleteByExpiryTimeBefore(captor.capture());

        LocalDateTime cutOff = captor.getValue();
        assertTrue(cutOff.isBefore(LocalDateTime.now()),
                "The cut-off must lie in the past so that a record is never removed too early");
    }

    @Test
    @DisplayName("Should not fail the schedule when the database is unavailable")
    void purgeExpiredOtpRecords_SurvivesADatabaseFailure() {
        when(otpRepository.deleteByExpiryTimeBefore(any(LocalDateTime.class)))
                .thenThrow(new DataAccessResourceFailureException("database unavailable"));

        cleanupService.purgeExpiredOtpRecords();
    }
}
