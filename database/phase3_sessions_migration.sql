-- =============================================================================
-- Phase 3 Sessions Migration: Persistent Session Tracking
-- Database: registration_db
-- Compatibility: MySQL 8.0+
-- -----------------------------------------------------------------------------
-- WHAT THIS SCRIPT DOES
--   * creates the 'sessions' table if it is not there yet
--   * creates the two supporting indexes if they are missing
--   * creates the foreign key to 'users' if it is missing
--
-- WHAT THIS SCRIPT DOES NOT DO
--   * it never drops a table
--   * it never drops or truncates a column
--   * it never deletes any row
--   * it never changes an existing 'users' table
--
-- It is safe to run on a database that already has the table (every statement is
-- guarded and reports what it skipped) and safe to run repeatedly.
--
-- WHEN TO RUN IT
--   * The table is created automatically by database/fresh_install.sql for a
--     brand-new database.
--   * Run this script on an EXISTING database that was created before Phase 3 and
--     therefore has no 'sessions' table.
--
--   & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p registration_db \
--       < database\phase3_sessions_migration.sql
--
-- NOTE: the 'jwt_token' column is deliberately left NULL by the application - only a
-- SHA-256 fingerprint of the token is stored in 'token_hash'.
-- =============================================================================

USE `registration_db`;

-- -----------------------------------------------------------------------------
-- 1. sessions table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `sessions` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `user_id` BIGINT NOT NULL,
    `token_hash` VARCHAR(64) NOT NULL,
    `jwt_token` VARCHAR(512) DEFAULT NULL,
    `login_time` DATETIME NOT NULL,
    `expiry_time` DATETIME NOT NULL,
    `is_revoked` BOOLEAN DEFAULT FALSE,
    `revoked_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    INDEX `idx_session_user` (`user_id`),
    INDEX `idx_session_token_hash` (`token_hash`),
    CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------------------------------
-- 2. Index on 'user_id' (used when revoking all sessions of a user)
-- -----------------------------------------------------------------------------
SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = DATABASE()
                     AND TABLE_NAME = 'sessions'
                     AND INDEX_NAME = 'idx_session_user');
SET @sql = IF(@idx_exists = 0,
              'ALTER TABLE `sessions` ADD INDEX `idx_session_user` (`user_id`)',
              'SELECT ''Index idx_session_user already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 3. Index on 'token_hash' (used on every authenticated request)
-- -----------------------------------------------------------------------------
SET @idx_exists = (SELECT COUNT(*) FROM information_schema.STATISTICS
                   WHERE TABLE_SCHEMA = DATABASE()
                     AND TABLE_NAME = 'sessions'
                     AND INDEX_NAME = 'idx_session_token_hash');
SET @sql = IF(@idx_exists = 0,
              'ALTER TABLE `sessions` ADD INDEX `idx_session_token_hash` (`token_hash`)',
              'SELECT ''Index idx_session_token_hash already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 4. Foreign key to 'users' (guarantees a session never outlives its account)
-- -----------------------------------------------------------------------------
SET @fk_exists = (SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
                  WHERE TABLE_SCHEMA = DATABASE()
                    AND TABLE_NAME = 'sessions'
                    AND CONSTRAINT_NAME = 'fk_sessions_user'
                    AND CONSTRAINT_TYPE = 'FOREIGN KEY');
SET @sql = IF(@fk_exists = 0,
              'ALTER TABLE `sessions` ADD CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE',
              'SELECT ''Foreign key fk_sessions_user already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 5. Verification (read-only)
-- -----------------------------------------------------------------------------
SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE()
   AND TABLE_NAME = 'sessions'
 ORDER BY ORDINAL_POSITION;
