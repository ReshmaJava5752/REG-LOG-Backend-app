package com.example.registrationlogin.repository;

import com.example.registrationlogin.entity.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {

    Optional<PasswordResetOtp> findTopByIdentifierOrderByCreatedAtDesc(String identifier);

    Optional<PasswordResetOtp> findByIdentifierAndResetToken(String identifier, String resetToken);

    void deleteByIdentifier(String identifier);

    /**
     * Deletes code records whose expiry time is before the given cut-off.
     *
     * <p>Used by the scheduled clean-up so that the table does not grow without bound. The
     * cut-off has to be far enough in the past that no row is removed while its single-use
     * reset token could still be redeemed.</p>
     */
    long deleteByExpiryTimeBefore(LocalDateTime cutoff);
}
