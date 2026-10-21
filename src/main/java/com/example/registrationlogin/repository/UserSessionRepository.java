package com.example.registrationlogin.repository;

import com.example.registrationlogin.entity.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Spring Data JPA access to the {@code sessions} table.
 *
 * <p>All lookups are keyed on {@code tokenHash} (the SHA-256 fingerprint of the JWT), never on
 * the raw token, because the raw token is not stored in the database.</p>
 */
@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    /**
     * Finds the most recent session for a token fingerprint.
     *
     * <p>{@code findFirst...OrderByIdDesc} is used rather than {@code findBy...} so that the
     * lookup keeps working even if a duplicate fingerprint was somehow written. The service
     * layer re-uses an existing row instead of inserting a second one, so duplicates should
     * never occur in the first place.</p>
     */
    Optional<UserSession> findFirstByTokenHashOrderByIdDesc(String tokenHash);

    /** All sessions of a user that have not been revoked. */
    List<UserSession> findAllByUserIdAndIsRevokedFalse(Long userId);

    /** Number of sessions of a user that are still active. */
    long countByUserIdAndIsRevokedFalse(Long userId);

    /** Deletes sessions that expired before the given cut-off. Returns the number removed. */
    long deleteByExpiryTimeBefore(LocalDateTime cutoff);
}
