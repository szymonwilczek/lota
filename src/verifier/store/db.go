// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite database management
//
// Manages database connection, schema migrations, and connection tuning.
// All SQLite-backed stores share a single database connection for consistency.
//
// Schema versioning ensures safe upgrades between verifier releases.
// Each migration runs in a transaction with automatic rollback on failure.
//
// IMPORTANT: Never modify existing migrations. Only append new ones.

package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// represents a single schema version upgrade
type migration struct {
	version     int
	description string
	sql         string
}

// schema migration history
// IMPORTANT: Append-only! Never modify existing migrations!
var migrations = []migration{
	{
		version:     1,
		description: "initial schema: clients, baselines, used_nonces",
		sql: `
			CREATE TABLE clients (
				id          TEXT PRIMARY KEY,
				aik_pem     TEXT NOT NULL,
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
		`,
	},
}

// opens or creates a SQLite database at the given path
// Applies pending schema migrations automatically.
func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// verify connectivity
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}

	// performance tuning for attestation workload
	pragmas := []string{
		"PRAGMA journal_mode=WAL",   // write-ahead logging for concurrent reads
		"PRAGMA busy_timeout=5000",  // wait up to 5s on lock contention
		"PRAGMA foreign_keys=ON",    // enforce referential integrity
		"PRAGMA synchronous=NORMAL", // safe with WAL mode
		"PRAGMA cache_size=-64000",  // 64MB page cache
		"PRAGMA temp_store=MEMORY",  // temp tables in memory
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", pragma, err)
		}
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
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
			tx.Rollback()
			return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.description, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
			m.version, time.Now().UTC(),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit migration %d: %w", m.version, err)
		}

		log.Printf("Applied migration %d: %s", m.version, m.description)
	}

	return nil
}

// returns the current database schema version
func SchemaVersion(db *sql.DB) (int, error) {
	var version int
	err := db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	return version, err
}
