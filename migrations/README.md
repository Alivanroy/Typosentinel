# Database Migrations

This directory contains SQL migration files for database schema management.

## Structure

Migration files should follow the naming convention:
```
YYYYMMDDHHMMSS_description.sql
```

For example:
```
20240101120000_create_users_table.sql
20240101130000_add_index_to_packages.sql
```

## Usage

Migrations are automatically applied when the application starts if `migrations.enabled` is set to `true` in the configuration.

## Migration Management

The application uses an embedded migration system that:
- Tracks applied migrations in the `schema_migrations` table
- Applies pending migrations in order
- Validates migration checksums to prevent tampering

## Adding New Migrations

1. Create a new SQL file with the appropriate timestamp and description
2. Place it in this directory
3. The migration will be automatically detected and applied on next startup

## Configuration

Migration settings can be configured in the application config:

```yaml
database:
  migrations_path: "./migrations"
  migrations_enabled: true
```