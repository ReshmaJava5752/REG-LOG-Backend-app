-- =============================================================================
-- Phase 2 Schema Migration: Mobile Number Support & Password Reset OTP Storage
-- Database: registration_db
-- Compatibility: MySQL 8.0+
-- Preserves all existing user records without data loss.
-- =============================================================================

USE `registration_db`;

-- 1. Safely add 'mobile_number' column to existing 'users' table if not present
-- Note: Uses MySQL 8.0+ IF NOT EXISTS syntax to avoid errors on repeated runs.
ALTER TABLE `users` ADD COLUMN IF NOT EXISTS `mobile_number` VARCHAR(15) UNIQUE;

-- 2. Create 'password_reset_otps' table if it does not already exist
CREATE TABLE IF NOT EXISTS `password_reset_otps` (
    `id` BIGINT NOT NULL AUTO_INCREMENT,
    `identifier` VARCHAR(150) NOT NULL,
    `otp_code` VARCHAR(10) NOT NULL,
    `expiry_time` DATETIME NOT NULL,
    `is_verified` BOOLEAN DEFAULT FALSE,
    `reset_token` VARCHAR(255) DEFAULT NULL,
    `attempts` INT DEFAULT 0,
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_otp_identifier` (`identifier`),
    INDEX `idx_otp_identifier_token` (`identifier`, `reset_token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
