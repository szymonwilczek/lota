// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - SQLite database management
//
// Manages database connection, schema migrations, and connection tuning.
// All SQLite-backed stores share a single database connection for consistency.
//
// Schema versioning ensures safe upgrades between verifier releases.
// Each migration runs in a transaction with automatic rollback on failure.
//
// Pre-v1.0: Schema is consolidated into a single migration.
// Post-v1.0: Append new migrations only. Never modify existing ones.

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	sqlite "modernc.org/sqlite"
)

// sqliteConstraintUnique and sqliteConstraintPrimaryKey are the extended
// SQLITE_CONSTRAINT result codes for a UNIQUE and a PRIMARY KEY violation.
// Matching the precise subtypes keeps a future non-uniqueness constraint
// on the same table from being misreported as a uniqueness violation,
// and mirrors the Postgres path that checks the precise SQLSTATE.
const (
	sqliteConstraintUnique     = 2067
	sqliteConstraintPrimaryKey = 1555
)

// pgUniqueViolation is the SQLSTATE for a Postgres unique_violation
const pgUniqueViolation = "23505"

// isSQLiteUniqueViolationCode reports whether an extended SQLite result code
// is a UNIQUE or PRIMARY KEY constraint violation.
func isSQLiteUniqueViolationCode(code int) bool {
	return code == sqliteConstraintUnique || code == sqliteConstraintPrimaryKey
}

// isUniqueViolation reports whether err is a unique / primary-key constraint
// violation from either backend.
// Global AIK-uniqueness index raises one when a concurrent registration wins
// the race after a caller's pre-check passed.
// Callers map it back to ErrAIKAlreadyRegistered so the race surfaces the same
// typed error as the sequential path.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return isSQLiteUniqueViolationCode(se.Code())
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code == pgUniqueViolation
	}
	return false
}

type sqliteConnector struct {
	driver *sqlite.Driver
	dsn    string
}

func (c *sqliteConnector) Connect(_ context.Context) (driver.Conn, error) {
	return c.driver.Open(c.dsn)
}

func (c *sqliteConnector) Driver() driver.Driver {
	return c.driver
}

// represents a single schema version upgrade
type migration struct {
	version     int
	description string
	sql         string
}

// schema migration history
// Pre-v1.0: single consolidated schema, no incremental migrations needed.
var migrations = []migration{
	{
		version:     1,
		description: "consolidated schema: clients, baselines, nonces, revocations, bans, audit, attestation log",
		sql: `
			CREATE TABLE clients (
				id          TEXT PRIMARY KEY,
				aik_der     BLOB NOT NULL,
				hardware_id BLOB,
				created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			);

			CREATE TABLE baselines (
				client_id    TEXT PRIMARY KEY,
				pcr14        BLOB NOT NULL CHECK(length(pcr14) = 32),
				first_seen   TIMESTAMP NOT NULL,
				last_seen    TIMESTAMP NOT NULL,
				attest_count INTEGER NOT NULL DEFAULT 1
			);

			CREATE TABLE used_nonces (
				nonce_hash TEXT PRIMARY KEY,
				used_at    TIMESTAMP NOT NULL
			);

			CREATE INDEX idx_used_nonces_used_at ON used_nonces(used_at);

			CREATE TABLE revocations (
				client_id  TEXT PRIMARY KEY,
				reason     TEXT NOT NULL,
				revoked_at TIMESTAMP NOT NULL,
				revoked_by TEXT NOT NULL DEFAULT '',
				note       TEXT NOT NULL DEFAULT ''
			);

			CREATE TABLE hardware_bans (
				hardware_id BLOB PRIMARY KEY CHECK(length(hardware_id) = 32),
				reason      TEXT NOT NULL,
				banned_at   TIMESTAMP NOT NULL,
				banned_by   TEXT NOT NULL DEFAULT '',
				note        TEXT NOT NULL DEFAULT ''
			);

			CREATE TABLE audit_log (
				id        INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TIMESTAMP NOT NULL,
				action    TEXT NOT NULL,
				target_id TEXT NOT NULL,
				reason    TEXT NOT NULL DEFAULT '',
				actor     TEXT NOT NULL DEFAULT '',
				note      TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
			CREATE INDEX idx_audit_log_target ON audit_log(target_id);

			CREATE TABLE attestation_log (
				id          INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp   TIMESTAMP NOT NULL,
				client_id   TEXT NOT NULL,
				hardware_id TEXT NOT NULL DEFAULT '',
				result      TEXT NOT NULL,
				duration_ms REAL NOT NULL DEFAULT 0,
				pcr14       TEXT NOT NULL DEFAULT '',
				details     TEXT NOT NULL DEFAULT '',
				remote_addr TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_attestation_log_timestamp ON attestation_log(timestamp);
			CREATE INDEX idx_attestation_log_client ON attestation_log(client_id);
			CREATE INDEX idx_attestation_log_result ON attestation_log(result);
		`,
	},
	{
		version:     2,
		description: "enforce global AIK uniqueness across clients",
		sql: `
			CREATE UNIQUE INDEX idx_clients_aik_der_unique ON clients(aik_der);
		`,
	},
	{
		version:     3,
		description: "pin firmware / SecureBoot PCRs (0, 1, 7) on baselines",
		sql: `
			ALTER TABLE baselines ADD COLUMN pcr0 BLOB;
			ALTER TABLE baselines ADD COLUMN pcr1 BLOB;
			ALTER TABLE baselines ADD COLUMN pcr7 BLOB;
			ALTER TABLE baselines ADD COLUMN boot_first_seen TIMESTAMP;
			ALTER TABLE baselines ADD COLUMN boot_last_seen  TIMESTAMP;
		`,
	},
	{
		version:     4,
		description: "pin agent self-hash for PCR14 boot-commitment derivation",
		sql: `
			ALTER TABLE baselines ADD COLUMN agent_hash BLOB;
		`,
	},
	{
		version: 5,
		description: "Self-service re-anchor: event-log baseline, ESRT " +
			"firmware version, assurance/rate-limit state, archive table",
		sql: `
			ALTER TABLE baselines ADD COLUMN eventlog_baseline BLOB;
			ALTER TABLE baselines ADD COLUMN esrt_version INTEGER;
			ALTER TABLE baselines ADD COLUMN esrt_capable INTEGER DEFAULT 0;
			ALTER TABLE baselines ADD COLUMN lfa INTEGER DEFAULT 0;
			ALTER TABLE baselines ADD COLUMN reanchor_count INTEGER DEFAULT 0;
			ALTER TABLE baselines ADD COLUMN last_reanchor_at TIMESTAMP;
			CREATE TABLE baseline_archive (
				id           INTEGER PRIMARY KEY AUTOINCREMENT,
				client_id    TEXT NOT NULL,
				archived_at  TIMESTAMP NOT NULL,
				pcr0         BLOB,
				pcr1         BLOB,
				pcr7         BLOB,
				esrt_version INTEGER,
				reason       TEXT
			);
			CREATE INDEX idx_baseline_archive_client ON baseline_archive(client_id);
		`,
	},
	{
		version:     6,
		description: "re-anchor: post-fact LFA review flag",
		sql: `
			ALTER TABLE baselines ADD COLUMN lfa_review_pending INTEGER DEFAULT 0;
		`,
	},
	{
		version:     7,
		description: "multi-tenancy: CA-assigned tenant on the baseline row",
		sql: `
			ALTER TABLE baselines ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			CREATE INDEX idx_baselines_tenant ON baselines(tenant);
		`,
	},
	{
		version: 8,
		description: "multi-tenancy: tenant on revocations, per-tenant " +
			"hardware bans keyed (tenant, hardware_id)",
		sql: `
			ALTER TABLE revocations ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			CREATE INDEX idx_revocations_tenant ON revocations(tenant);
			CREATE TABLE hardware_bans_new (
				tenant      TEXT NOT NULL,
				hardware_id BLOB NOT NULL CHECK(length(hardware_id) = 32),
				reason      TEXT NOT NULL,
				banned_at   TIMESTAMP NOT NULL,
				banned_by   TEXT NOT NULL DEFAULT '',
				note        TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (tenant, hardware_id)
			);
			INSERT INTO hardware_bans_new (tenant, hardware_id, reason, banned_at, banned_by, note)
				SELECT 'default', hardware_id, reason, banned_at, banned_by, note FROM hardware_bans;
			DROP TABLE hardware_bans;
			ALTER TABLE hardware_bans_new RENAME TO hardware_bans;
			CREATE INDEX idx_hardware_bans_tenant ON hardware_bans(tenant);
		`,
	},
}

// opens or creates a SQLite database at the given path
// Applies pending schema migrations automatically.
func OpenDB(path string) (*sql.DB, error) {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",   // write-ahead logging for concurrent reads
		"PRAGMA busy_timeout=5000",  // wait up to 5s on lock contention
		"PRAGMA foreign_keys=ON",    // enforce referential integrity
		"PRAGMA synchronous=NORMAL", // safe with WAL mode
		"PRAGMA cache_size=-64000",  // 64MB page cache
		"PRAGMA temp_store=MEMORY",  // temp tables in memory
	}

	if path != "" && path != ":memory:" {
		dir := filepath.Dir(path)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("failed to create database directory %q: %w", dir, err)
			}
		}
	}

	sqliteDriver := &sqlite.Driver{}
	sqliteDriver.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, _ string) error {
		ctx := context.Background()
		for _, pragma := range pragmas {
			if _, err := conn.ExecContext(ctx, pragma, nil); err != nil {
				return fmt.Errorf("failed to set pragma %q: %w", pragma, err)
			}
		}
		return nil
	})

	db := sql.OpenDB(&sqliteConnector{driver: sqliteDriver, dsn: path})

	// verify connectivity
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(0)

	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// applies pending schema migrations inside transactions
func runMigrations(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_version (
			version    INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	var current int
	if err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current); err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("migration %d (%s) failed: %w; rollback failed: %v", m.version, m.description, err, rbErr)
			}
			return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.description, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
			m.version, time.Now().UTC(),
		); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("failed to record migration %d: %w; rollback failed: %v", m.version, err, rbErr)
			}
			return fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", m.version, err)
		}

		slog.Info("applied database migration", "version", m.version, "description", m.description)
	}

	return nil
}

// returns the current database schema version
func SchemaVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	return version, err
}
