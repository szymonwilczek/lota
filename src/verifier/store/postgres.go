// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL database management
//
// Postgres backend for multi-instance / high-availability deployments.
// The SQLite backend (db.go) stays the single-node default; this layer
// gives the same store interfaces a shared backend that several verifier
// instances behind a load balancer can point at.
//
// The driver is pgx in its database/sql-compatible mode, so the store
// implementations stay on *sql.DB like the SQLite ones.
//
// Placeholders are $N (Postgres) rather than ? (SQLite), so the Postgres
// store code lives in its own pg_*.go files instead of being shared.

package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

// holds the Postgres schema history
var pgMigrations = []migration{
	{
		version:     1,
		description: "consolidated schema: clients, baselines, nonces, revocations, bans, audit, attestation log",
		sql: `
			CREATE TABLE clients (
				id          TEXT PRIMARY KEY,
				aik_der     BYTEA NOT NULL,
				hardware_id BYTEA,
				created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
			);

			CREATE UNIQUE INDEX idx_clients_aik_der_unique ON clients(aik_der);

			CREATE TABLE baselines (
				client_id       TEXT PRIMARY KEY,
				pcr14           BYTEA NOT NULL CHECK(octet_length(pcr14) = 32),
				first_seen      TIMESTAMPTZ NOT NULL,
				last_seen       TIMESTAMPTZ NOT NULL,
				attest_count    BIGINT NOT NULL DEFAULT 1,
				pcr0            BYTEA,
				pcr1            BYTEA,
				pcr7            BYTEA,
				boot_first_seen TIMESTAMPTZ,
				boot_last_seen  TIMESTAMPTZ,
				agent_hash      BYTEA
			);

			CREATE TABLE used_nonces (
				nonce_hash TEXT PRIMARY KEY,
				used_at    TIMESTAMPTZ NOT NULL
			);

			CREATE INDEX idx_used_nonces_used_at ON used_nonces(used_at);

			CREATE TABLE revocations (
				client_id  TEXT PRIMARY KEY,
				reason     TEXT NOT NULL,
				revoked_at TIMESTAMPTZ NOT NULL,
				revoked_by TEXT NOT NULL DEFAULT '',
				note       TEXT NOT NULL DEFAULT ''
			);

			CREATE TABLE hardware_bans (
				hardware_id BYTEA PRIMARY KEY CHECK(octet_length(hardware_id) = 32),
				reason      TEXT NOT NULL,
				banned_at   TIMESTAMPTZ NOT NULL,
				banned_by   TEXT NOT NULL DEFAULT '',
				note        TEXT NOT NULL DEFAULT ''
			);

			CREATE TABLE audit_log (
				id        BIGSERIAL PRIMARY KEY,
				timestamp TIMESTAMPTZ NOT NULL,
				action    TEXT NOT NULL,
				target_id TEXT NOT NULL,
				reason    TEXT NOT NULL DEFAULT '',
				actor     TEXT NOT NULL DEFAULT '',
				note      TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
			CREATE INDEX idx_audit_log_target ON audit_log(target_id);

			CREATE TABLE attestation_log (
				id          BIGSERIAL PRIMARY KEY,
				timestamp   TIMESTAMPTZ NOT NULL,
				client_id   TEXT NOT NULL,
				hardware_id TEXT NOT NULL DEFAULT '',
				result      TEXT NOT NULL,
				duration_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
				pcr14       TEXT NOT NULL DEFAULT '',
				details     TEXT NOT NULL DEFAULT '',
				remote_addr TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_attestation_log_timestamp ON attestation_log(timestamp);
			CREATE INDEX idx_attestation_log_client ON attestation_log(client_id);
			CREATE INDEX idx_attestation_log_result ON attestation_log(result);

			CREATE TABLE session_tokens (
				token_hash  BYTEA PRIMARY KEY CHECK(octet_length(token_hash) = 32),
				client_id   TEXT NOT NULL,
				hardware_id BYTEA NOT NULL,
				valid_until BIGINT NOT NULL,
				result_code BIGINT NOT NULL,
				flags       BIGINT NOT NULL,
				pcr_mask    BIGINT NOT NULL,
				consumed    BOOLEAN NOT NULL DEFAULT FALSE
			);

			CREATE INDEX idx_session_tokens_valid_until ON session_tokens(valid_until);
		`,
	},
	{
		version: 2,
		description: "Self-service re-anchor: event-log baseline, ESRT " +
			"firmware version, assurance/rate-limit state, archive table",
		sql: `
			ALTER TABLE baselines ADD COLUMN eventlog_baseline BYTEA;
			ALTER TABLE baselines ADD COLUMN esrt_version BIGINT;
			ALTER TABLE baselines ADD COLUMN esrt_capable BOOLEAN NOT NULL DEFAULT FALSE;
			ALTER TABLE baselines ADD COLUMN lfa BOOLEAN NOT NULL DEFAULT FALSE;
			ALTER TABLE baselines ADD COLUMN reanchor_count BIGINT NOT NULL DEFAULT 0;
			ALTER TABLE baselines ADD COLUMN last_reanchor_at TIMESTAMPTZ;

			CREATE TABLE baseline_archive (
				id           BIGSERIAL PRIMARY KEY,
				client_id    TEXT NOT NULL,
				archived_at  TIMESTAMPTZ NOT NULL,
				pcr0         BYTEA,
				pcr1         BYTEA,
				pcr7         BYTEA,
				esrt_version BIGINT,
				reason       TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_baseline_archive_client ON baseline_archive(client_id);
		`,
	},
	{
		version:     3,
		description: "re-anchor: post-fact LFA review flag",
		sql: `
			ALTER TABLE baselines ADD COLUMN lfa_review_pending BOOLEAN NOT NULL DEFAULT FALSE;
		`,
	},
	{
		version:     4,
		description: "multi-tenancy: CA-assigned tenant on the baseline row",
		sql: `
			ALTER TABLE baselines ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			CREATE INDEX idx_baselines_tenant ON baselines(tenant);
		`,
	},
	{
		version: 5,
		description: "multi-tenancy: tenant on revocations, per-tenant " +
			"hardware bans keyed (tenant, hardware_id)",
		sql: `
			ALTER TABLE revocations ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			CREATE INDEX idx_revocations_tenant ON revocations(tenant);
			ALTER TABLE hardware_bans ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			ALTER TABLE hardware_bans DROP CONSTRAINT hardware_bans_pkey;
			ALTER TABLE hardware_bans ADD PRIMARY KEY (tenant, hardware_id);
		`,
	},
	{
		version: 6,
		description: "multi-tenancy: tenant on the audit and attestation " +
			"logs and on session tokens",
		sql: `
			ALTER TABLE audit_log ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			ALTER TABLE attestation_log ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			ALTER TABLE session_tokens ADD COLUMN tenant TEXT NOT NULL DEFAULT 'default';
			CREATE INDEX idx_audit_log_tenant ON audit_log(tenant);
			CREATE INDEX idx_attestation_log_tenant ON attestation_log(tenant);
		`,
	},
	{
		version: 7,
		description: "sharding: per-database identity and the control " +
			"database's pinned shard set",
		sql: `
			CREATE TABLE shard_identity (
				singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
				id         TEXT NOT NULL,
				created_at TIMESTAMPTZ NOT NULL DEFAULT now()
			);
			CREATE TABLE shard_set (
				singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
				fingerprint TEXT NOT NULL,
				shard_count INTEGER NOT NULL,
				created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
			);
		`,
	},
}

// OpenPostgresDB opens a Postgres-backed store at the given DSN and applies
// pending schema migrations.
//
// DSN is a libpq/pgx connection string, e.g:
// "postgres://user:pass@host:5432/lota?sslmode=verify-full"
//
// Connection pooling is left to database/sql; the pool is sized for the
// per-instance attestation concurrency, not the whole fleet, because every
// verifier instance opens its own pool against the shared server.
func OpenPostgresDB(dsn string) (*sql.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres DSN is empty")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres ping failed: %w", err)
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := runPgMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres migration failed: %w", err)
	}

	return db, nil
}

// runPgMigrations applies pending Postgres schema migrations, each inside its
// own transaction with rollback on failure.
// Session-level advisory lock serializes concurrent verifier instances racing
// the first migration so the consolidated schema is created exactly once.
func runPgMigrations(db *sql.DB) error {
	// 0x6C6F7461 = "lota"; arbitrary stable key for the migration advisory lock.
	const migrationLockKey = 0x6C6F7461

	ctx := context.Background()

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire migration connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrationLockKey); err != nil {
		return fmt.Errorf("failed to take migration advisory lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrationLockKey); err != nil {
			slog.Warn("failed to release migration advisory lock", "error", err)
		}
	}()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version    INTEGER PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_version table: %w", err)
	}

	var current int
	if err := conn.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current); err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	for _, m := range pgMigrations {
		if m.version <= current {
			continue
		}

		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return fmt.Errorf("migration %d (%s) failed: %w; rollback failed: %v", m.version, m.description, err, rbErr)
			}
			return fmt.Errorf("migration %d (%s) failed: %w", m.version, m.description, err)
		}

		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_version (version, applied_at) VALUES ($1, $2)",
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

		slog.Info("applied postgres migration", "version", m.version, "description", m.description)
	}

	return nil
}
