-- ============================================
-- SecureTrack Database Schema
-- File Access Monitoring & Object Protection
-- ============================================

CREATE DATABASE IF NOT EXISTS securetrack
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE securetrack;

-- Drop existing tables in reverse dependency order
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS file_events;
DROP TABLE IF EXISTS protected_objects;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS users;

-- ============================================
-- USERS TABLE
-- ============================================
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Administrator', 'Third-Party User') NOT NULL DEFAULT 'Third-Party User',
    status ENUM('Active', 'Inactive') NOT NULL DEFAULT 'Active',
    last_login DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================
-- PASSWORD RESETS TABLE
-- ============================================
CREATE TABLE password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- PROTECTED OBJECTS TABLE
-- ============================================
CREATE TABLE protected_objects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    path VARCHAR(512) NOT NULL,
    object_type ENUM('File', 'Folder') NOT NULL DEFAULT 'File',
    original_hash VARCHAR(128) NULL,
    current_hash VARCHAR(128) NULL,
    monitoring_status ENUM('Active', 'Inactive') NOT NULL DEFAULT 'Active',
    integrity_status ENUM('Verified', 'Changed', 'Unknown') NOT NULL DEFAULT 'Unknown',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================
-- FILE EVENTS TABLE
-- ============================================
CREATE TABLE file_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    protected_object_id INT NOT NULL,
    user_id INT NULL,
    event_type ENUM('Created', 'Modified', 'Deleted', 'Renamed', 'Moved', 'Viewed', 'Accessed', 'Downloaded') NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    previous_hash VARCHAR(128) NULL,
    new_hash VARCHAR(128) NULL,
    risk_level ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Low',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (protected_object_id) REFERENCES protected_objects(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================
-- AUDIT LOGS TABLE
-- ============================================
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(255) NOT NULL,
    object_type VARCHAR(100) NULL,
    object_id INT NULL,
    description TEXT NULL,
    ip_address VARCHAR(45) NULL,
    status ENUM('Success', 'Failed') NOT NULL DEFAULT 'Success',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ============================================
-- ALERTS TABLE
-- ============================================
CREATE TABLE alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_id INT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL DEFAULT 'Medium',
    status ENUM('New', 'Acknowledged', 'Investigating', 'Resolved') NOT NULL DEFAULT 'New',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    resolved_at DATETIME NULL,
    FOREIGN KEY (event_id) REFERENCES file_events(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ============================================
-- PERMISSIONS TABLE
-- ============================================
CREATE TABLE permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    protected_object_id INT NOT NULL,
    permission_type ENUM('View', 'Access', 'Download', 'Modify', 'Delete') NOT NULL DEFAULT 'View',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (protected_object_id) REFERENCES protected_objects(id) ON DELETE CASCADE,
    UNIQUE KEY unique_permission (user_id, protected_object_id, permission_type)
) ENGINE=InnoDB;

-- ============================================
-- INDEXES for performance
-- ============================================
CREATE INDEX idx_file_events_object ON file_events(protected_object_id);
CREATE INDEX idx_file_events_user ON file_events(user_id);
CREATE INDEX idx_file_events_type ON file_events(event_type);
CREATE INDEX idx_file_events_created ON file_events(created_at);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created ON alerts(created_at);
CREATE INDEX idx_permissions_user ON permissions(user_id);
CREATE INDEX idx_protected_objects_status ON protected_objects(monitoring_status);
