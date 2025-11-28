-- Schema migrations table (created by code as well, kept for completeness)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    applied_at TIMESTAMP NOT NULL
);

-- Example table to ensure migrations/*.sql exists
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    project_path TEXT NOT NULL,
    total_packages INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL
);

