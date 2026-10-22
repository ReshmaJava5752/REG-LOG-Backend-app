-- =============================================================================
-- Phase 3 Schema Migration: Updated Timestamp & Persistent Session Tracking
-- Database: registration_db
-- Compatibility: MySQL 8.0+
-- Preserves all existing user and OTP records without data loss.
-- =============================================================================

USE `registration_db`;

-- 1. Safely add 'updated_at' column to 'users' table if not present
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

-- 2. Create 'sessions' table for persistent JWT session tracking
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
