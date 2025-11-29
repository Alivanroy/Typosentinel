-- Initial database schema for Typosentinel
-- Creates tables for scans, threats, and metadata

-- Create package_scans table
CREATE TABLE IF NOT EXISTS package_scans (
    id TEXT PRIMARY KEY,
    package_name TEXT NOT NULL,
    version TEXT,
    registry TEXT,
    status TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    duration INTEGER,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create threats table
CREATE TABLE IF NOT EXISTS threats (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL,
    description TEXT,
    source TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES package_scans(id) ON DELETE CASCADE
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_package_scans_package_name ON package_scans(package_name);
CREATE INDEX IF NOT EXISTS idx_package_scans_status ON package_scans(status);
CREATE INDEX IF NOT EXISTS idx_package_scans_started_at ON package_scans(started_at);
CREATE INDEX IF NOT EXISTS idx_threats_scan_id ON threats(scan_id);
CREATE INDEX IF NOT EXISTS idx_threats_package_name ON threats(package_name);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(type);