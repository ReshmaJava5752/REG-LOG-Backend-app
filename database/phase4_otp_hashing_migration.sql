-- =============================================================================
-- Phase 4 Migration: Secure Storage of Password Reset Codes
-- Database: registration_db
-- Compatibility: MySQL 8.0+
-- -----------------------------------------------------------------------------
-- WHY THIS MIGRATION IS NEEDED
--   The 'otp_code' column used to hold the 6 digit reset code in plain text.
--   It now holds an HMAC-SHA256 fingerprint of the code, which is 64 characters
--   long, so the column has to be widened from VARCHAR(10) to VARCHAR(64).
--
-- WHAT THIS SCRIPT DOES
--   * widens 'password_reset_otps.otp_code' to VARCHAR(64)
--   * nothing else
--
-- WHAT THIS SCRIPT DOES NOT DO
--   * it does not drop or truncate any table
--   * it does not delete any row
--   * it does not change any other column
--
-- The statement is guarded: it only runs when the column is still narrower than
-- 64 characters, so it is safe to run repeatedly and on a database that has
-- already been migrated.
--
--   & "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p registration_db \
--       < database\phase4_otp_hashing_migration.sql
--
-- NOTE ON EXISTING ROWS
--   Rows that were written before the migration still contain the plain code.
--   The application accepts them for the remainder of their (5 minute) lifetime
--   and never writes a plain code itself. Run the script before starting the
--   updated backend, otherwise the fingerprint does not fit into the column.
-- =============================================================================

USE `registration_db`;

SET @col_len = (SELECT CHARACTER_MAXIMUM_LENGTH
                  FROM information_schema.COLUMNS
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
-- Verification (read-only)
-- -----------------------------------------------------------------------------
SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = DATABASE()
   AND TABLE_NAME = 'password_reset_otps'
   AND COLUMN_NAME = 'otp_code';
