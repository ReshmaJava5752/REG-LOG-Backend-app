package com.example.registrationlogin.service;

import com.example.registrationlogin.repository.PasswordResetOtpRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Removes password-reset code records that can no longer be used.
 *
 * <p>Every password-recovery request writes a code record - also for an address that belongs
 * to no account, so that the verification endpoint cannot be used to find out which addresses
 * are registered. Those records are short lived, and without a clean-up the table would grow
 * with every request that is ever made.</p>
 *
 * <p>A record is only removed once its expiry is far enough in the past that its single-use
 * reset token can no longer be redeemed, so a clean-up can never break a recovery that is
 * still in progress.</p>
 */
@Service
public class OtpCleanupService {

    private static final Logger log = LoggerFactory.getLogger(OtpCleanupService.class);

    /**
     * How long a record is kept after its expiry. It has to be longer than the window in
     * which a reset token is still accepted (10 minutes).
     */
    @Value("${app.otp.cleanup-retention-minutes:15}")
    private long retentionMinutes = 15;

    private final PasswordResetOtpRepository otpRepository;

    @Autowired
    public OtpCleanupService(PasswordResetOtpRepository otpRepository) {
        this.otpRepository = otpRepository;
    }

    /**
     * Scheduled clean-up of code records that can no longer be used.
     */
    @Transactional
    @Scheduled(cron = "${app.otp.cleanup-cron:0 30 * * * *}")
    public void purgeExpiredOtpRecords() {
        try {
            LocalDateTime cutoff = LocalDateTime.now().minusMinutes(Math.max(retentionMinutes, 1));
            long removed = otpRepository.deleteByExpiryTimeBefore(cutoff);
            if (removed > 0) {
                log.info("Removed {} expired password reset code record(s).", removed);
            }
        } catch (DataAccessException ex) {
            log.error("Could not purge expired password reset code records (exception={}).",
                    ex.getClass().getSimpleName());
        }
    }
}
