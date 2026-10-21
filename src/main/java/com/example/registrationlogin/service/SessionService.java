package com.example.registrationlogin.service;

import com.example.registrationlogin.entity.User;
import com.example.registrationlogin.entity.UserSession;
import com.example.registrationlogin.repository.UserSessionRepository;
import com.example.registrationlogin.util.TokenHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Persistent store of issued login sessions, backed by the {@code sessions} table.
 *
 * <p>This is the durable half of the token invalidation story. {@code TokenBlacklistService}
 * keeps the in-memory revocation list, which is lost whenever the backend restarts. This
 * service stores the same information in the database, so a token that was revoked by a
 * logout, a password change or a password reset stays revoked across restarts and across
 * multiple backend instances.</p>
 *
 * <h2>Graceful cutover</h2>
 * <p>Tokens that were issued <em>before</em> this feature was deployed have no session row.
 * They are treated as active until their own JWT expiry (at most
 * {@code app.jwt.expiration-ms}, 24 hours by default) so that enabling the feature does not
 * force existing users to log in again. Once a user logs in again their new token gets a
 * session row and becomes fully revocable. No secret is rotated and no token is invalidated
 * by the upgrade itself.</p>
 *
 * <h2>Failure behaviour</h2>
 * <p>Every write runs in its own transaction ({@link Propagation#REQUIRES_NEW}) so that a
 * problem in the session store can never roll back the surrounding business transaction - a
 * password reset still succeeds even if the session table is unreachable. The in-memory
 * revocation list then keeps the deployment secure for the remainder of its uptime, and the
 * failure is reported in the server log.</p>
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);

    private final UserSessionRepository sessionRepository;

    /** Allows persistent session tracking to be switched off without a code change. */
    @Value("${app.session.enabled:true}")
    private boolean sessionEnabled = true;

    /**
     * Creates an instance backed by the database.
     */
    @Autowired
    public SessionService(UserSessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    /**
     * Creates an instance without a persistent backing store.
     *
     * <p>Used by the legacy constructor of {@code UserServiceImpl} so that unit tests which
     * build the service by hand keep working unchanged. In this mode every session operation
     * is a no-op and {@link #isSessionActive(String)} always reports the session as active,
     * which reproduces exactly the behaviour the project had before persistent sessions
     * were introduced.</p>
     */
    public static SessionService disabled() {
        return new SessionService(null);
    }

    private boolean isPersistenceEnabled() {
        return sessionRepository != null && sessionEnabled;
    }

    /**
     * Records a newly issued session for a successful login.
     *
     * <p>When a row for the same token fingerprint already exists it is re-used and
     * re-activated instead of being duplicated. This can happen because the JWT payload only
     * carries second precision, so two logins in the same second produce an identical token.</p>
     *
     * @param user        the account the session belongs to
     * @param jwtToken    the raw token - only its fingerprint is stored
     * @param expiryDate  the expiry of the JWT
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerSession(User user, String jwtToken, Date expiryDate) {
        if (!isPersistenceEnabled() || user == null || jwtToken == null || jwtToken.isBlank()) {
            return;
        }

        String tokenHash = TokenHasher.sha256Hex(jwtToken);
        LocalDateTime loginTime = LocalDateTime.now();
        LocalDateTime expiryTime = expiryDate != null
                ? LocalDateTime.ofInstant(expiryDate.toInstant(), ZoneId.systemDefault())
                : loginTime.plusDays(1);

        Optional<UserSession> existing = sessionRepository.findFirstByTokenHashOrderByIdDesc(tokenHash);

        if (existing.isPresent()) {
            UserSession session = existing.get();
            session.setUserId(user.getId());
            session.setLoginTime(loginTime);
            session.setExpiryTime(expiryTime);
            session.setIsRevoked(false);
            session.setRevokedAt(null);
            sessionRepository.save(session);
            return;
        }

        UserSession session = new UserSession(user.getId(), tokenHash, loginTime, expiryTime);
        sessionRepository.save(session);
    }

    /**
     * Tells whether the given token still corresponds to an active session.
     *
     * <p>Returns {@code true} when:</p>
     * <ul>
     *   <li>the token has no session row at all - it was issued before this feature was
     *       deployed, so it is honoured until its own expiry (graceful cutover); or</li>
     *   <li>a session row exists that has not been revoked and has not expired yet.</li>
     * </ul>
     *
     * <p>Returns {@code false} when the session was revoked (logout, password change or
     * password reset) or when the recorded expiry has passed.</p>
     */
    public boolean isSessionActive(String jwtToken) {
        if (!isPersistenceEnabled()) {
            return true;
        }
        if (jwtToken == null || jwtToken.isBlank()) {
            return false;
        }

        try {
            String tokenHash = TokenHasher.sha256Hex(jwtToken);
            Optional<UserSession> found = sessionRepository.findFirstByTokenHashOrderByIdDesc(tokenHash);

            if (found.isEmpty()) {
                // No record: a token issued before persistent sessions were enabled.
                return true;
            }

            return found.get().isActiveAt(LocalDateTime.now());
        } catch (DataAccessException ex) {
            // Degrade to the in-memory revocation list rather than locking everyone out.
            log.error("Session store unavailable (exception={}); falling back to the in-memory revocation list.",
                    ex.getClass().getSimpleName());
            return true;
        }
    }

    /**
     * Revokes the session belonging to the given token. Called on logout.
     *
     * @return {@code true} when a session row was found and revoked
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean revokeSession(String jwtToken) {
        if (!isPersistenceEnabled() || jwtToken == null || jwtToken.isBlank()) {
            return false;
        }

        String tokenHash = TokenHasher.sha256Hex(jwtToken);

        Optional<UserSession> found = sessionRepository.findFirstByTokenHashOrderByIdDesc(tokenHash);
        if (found.isEmpty()) {
            // Legacy token without a session row - nothing to revoke in the database.
            return false;
        }

        UserSession session = found.get();
        session.revoke();
        sessionRepository.save(session);
        return true;
    }

    /**
     * Revokes every active session of a user. Called on password change and password reset so
     * that a stolen token cannot outlive the credentials it was issued for.
     *
     * @return the number of sessions that were revoked
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public int revokeAllSessions(Long userId) {
        if (!isPersistenceEnabled() || userId == null) {
            return 0;
        }

        List<UserSession> active = sessionRepository.findAllByUserIdAndIsRevokedFalse(userId);
        if (active.isEmpty()) {
            return 0;
        }

        for (UserSession session : active) {
            session.revoke();
        }
        sessionRepository.saveAll(active);
        return active.size();
    }

    /**
     * Counts the sessions of a user that are still active.
     */
    public long countActiveSessions(Long userId) {
        if (!isPersistenceEnabled() || userId == null) {
            return 0L;
        }
        return sessionRepository.countByUserIdAndIsRevokedFalse(userId);
    }

    /**
     * Removes sessions whose expiry time has passed. Runs on a schedule so the table does not
     * grow without bound.
     *
     * @return the number of rows that were removed
     */
    @Transactional
    public int purgeExpiredSessions() {
        if (!isPersistenceEnabled()) {
            return 0;
        }
        return (int) sessionRepository.deleteByExpiryTimeBefore(LocalDateTime.now());
    }

    /**
     * Scheduled clean-up of expired session records.
     *
     * <p>The schedule is configurable with {@code app.session.purge-cron} and defaults to
     * once per hour.</p>
     */
    @Transactional
    @Scheduled(cron = "${app.session.purge-cron:0 0 * * * *}")
    public void purgeExpiredSessionsOnSchedule() {
        if (!isPersistenceEnabled()) {
            return;
        }
        try {
            long removed = sessionRepository.deleteByExpiryTimeBefore(LocalDateTime.now());
            if (removed > 0) {
                log.info("Removed {} expired session record(s).", removed);
            }
        } catch (DataAccessException ex) {
            log.error("Could not purge expired sessions (exception={}).",
                    ex.getClass().getSimpleName());
        }
    }
}
