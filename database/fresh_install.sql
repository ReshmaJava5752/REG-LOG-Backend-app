-- =============================================================================
-- Fresh Install: Complete Schema for the Registration & Login System
-- Database: registration_db
-- Compatibility: MySQL 8.0+
-- -----------------------------------------------------------------------------
-- Use this script when you are setting up a BRAND-NEW database:
--
--   & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p \
--       < database\fresh_install.sql
--
-- It creates the database and all three tables exactly as the JPA entities
-- expect them, including the Phase 2 columns (mobile_number, password_reset_otps)
-- and the Phase 3 additions (updated_at, sessions).
--
-- The script is NON-DESTRUCTIVE:
--   * it never drops a table and never drops a column
--   * CREATE TABLE IF NOT EXISTS is used throughout
--   * the two guarded ALTER statements only ADD a column when it is missing
--
-- If you already have a database\phase2_migration.sql or
-- phase3_migration.sql migration history, running this script is still safe -
-- every statement is idempotent.
--
-- NOTE: the application runs with spring.jpa.hibernate.ddl-auto=none, so the
-- schema is owned entirely by these scripts. Hibernate never alters it.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0. Database
-- -----------------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS `registration_db`
    DEFAULT CHARACTER SET utf8mb4
    COLLATE utf8mb4_0900_ai_ci;

USE `registration_db`;

-- -----------------------------------------------------------------------------
-- 1. users
--    Entity: com.example.registrationlogin.entity.User
--    Note: 'updated_at' is also maintained by MySQL via ON UPDATE
--          CURRENT_TIMESTAMP; Hibernate sets it explicitly in @PreUpdate.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `full_name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(150) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `mobile_number` VARCHAR(15) DEFAULT NULL,
    `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `email` (`email`),
    UNIQUE KEY `mobile_number` (`mobile_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------------------------------
-- 2. Guarded ALTERs - bring a pre-Phase-2 'users' table up to date.
--    Each statement is skipped when the column already exists.
-- -----------------------------------------------------------------------------
-- 2a. mobile_number (Phase 2)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA = DATABASE()
                     AND TABLE_NAME = 'users'
                     AND COLUMN_NAME = 'mobile_number');
SET @sql = IF(@col_exists = 0,
              'ALTER TABLE `users` ADD COLUMN `mobile_number` VARCHAR(15) UNIQUE',
              'SELECT ''Column mobile_number already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 2b. updated_at (Phase 3)
SET @col_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS
                   WHERE TABLE_SCHEMA = DATABASE()
                     AND TABLE_NAME = 'users'
                     AND COLUMN_NAME = 'updated_at');
SET @sql = IF(@col_exists = 0,
              'ALTER TABLE `users` ADD COLUMN `updated_at` DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP',
              'SELECT ''Column updated_at already exists''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 3. password_reset_otps
--    Entity: com.example.registrationlogin.entity.PasswordResetOtp
--    Note: 'otp_code' holds the HMAC-SHA256 fingerprint of the reset code, never the
--          code itself, so it needs 64 characters. The width is also corrected here for
--          an existing table that was created with the older, narrower definition.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `password_reset_otps` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `identifier` VARCHAR(150) NOT NULL,
    `otp_code` VARCHAR(64) NOT NULL,
    `expiry_time` DATETIME NOT NULL,
    `is_verified` BOOLEAN DEFAULT FALSE,
    `reset_token` VARCHAR(255) DEFAULT NULL,
    `attempts` INT DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_otp_identifier` (`identifier`),
    INDEX `idx_otp_identifier_token` (`identifier`, `reset_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- -----------------------------------------------------------------------------
-- 3b. Guarded widening of 'otp_code' - the column holds the fingerprint of the reset
--     code, so it needs 64 characters. It is only changed when it is still narrower,
--     which repairs a table that was created with the older definition.
-- -----------------------------------------------------------------------------
SET @col_len = (SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'password_reset_otps'
                  AND COLUMN_NAME = 'otp_code');
SET @sql = IF(@col_len IS NOT NULL AND @col_len < 64,
              'ALTER TABLE `password_reset_otps` MODIFY COLUMN `otp_code` VARCHAR(64) NOT NULL',
              'SELECT ''Column otp_code already has the required width''');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- -----------------------------------------------------------------------------
-- 4. sessions
--    Persistent JWT session tracking. Every successful login writes a row here so a
--    revoked token stays revoked across a backend restart. The row holds a SHA-256
--    fingerprint of the token; the jwt_token column is deliberately left NULL.
--    See the "Persistent Sessions" section in README.md.
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
    CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- =============================================================================
-- Done. Verify with:
--   SELECT TABLE_NAME FROM information_schema.TABLES
--    WHERE TABLE_SCHEMA = 'registration_db';
-- =============================================================================
