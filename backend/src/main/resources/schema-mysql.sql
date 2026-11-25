-- Runs after Hibernate's schema update. Increment 1 created google_id as NOT NULL; email/password
-- accounts (Increment 2) have no Google id. Safe to run repeatedly (MySQL 8 and MariaDB).
ALTER TABLE users MODIFY google_id VARCHAR(64) NULL;
