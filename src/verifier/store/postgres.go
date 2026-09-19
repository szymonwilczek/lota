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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx"
)

// Holds the Postgres schema history.
// One consolidated schema: verifier creates the database at its final shape.
// runPgMigrations stays so post-1.0 change can append entry.
var pgMigrations = []migration{
	{
		version:     1,
		description: "consolidated schema: clients, baselines, nonces, revocations, bans, audit, attestation log, sharding",
		sql: `
			CREATE TABLE clients (
				id          TEXT PRIMARY KEY,
				aik_der     BYTEA NOT NULL,
				hardware_id BYTEA,
				created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
			);

			CREATE UNIQUE INDEX idx_clients_aik_der_unique ON clients(aik_der);

			CREATE TABLE baselines (
				client_id                TEXT PRIMARY KEY,
				pcr14                    BYTEA NOT NULL CHECK(octet_length(pcr14) = 32),
				first_seen               TIMESTAMPTZ NOT NULL,
				last_seen                TIMESTAMPTZ NOT NULL,
				attest_count             BIGINT NOT NULL DEFAULT 1,
				pcr0                     BYTEA,
				pcr1                     BYTEA,
				pcr7                     BYTEA,
				boot_first_seen          TIMESTAMPTZ,
				boot_last_seen           TIMESTAMPTZ,
				agent_hash               BYTEA,
				eventlog_baseline        BYTEA,
				esrt_version             BIGINT,
				esrt_capable             BOOLEAN NOT NULL DEFAULT FALSE,
				lfa                      BOOLEAN NOT NULL DEFAULT FALSE,
				reanchor_count           BIGINT NOT NULL DEFAULT 0,
				last_reanchor_at         TIMESTAMPTZ,
				lfa_review_pending       BOOLEAN NOT NULL DEFAULT FALSE,
				tenant                   TEXT NOT NULL DEFAULT 'default',
				agent_hash_repin_count   BIGINT NOT NULL DEFAULT 0,
				last_agent_hash_repin_at TIMESTAMPTZ,
				kernel_hash              BYTEA
			);

			CREATE INDEX idx_baselines_tenant ON baselines(tenant);

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
				note       TEXT NOT NULL DEFAULT '',
				tenant     TEXT NOT NULL DEFAULT 'default'
			);

			CREATE INDEX idx_revocations_tenant ON revocations(tenant);

			CREATE TABLE hardware_bans (
				tenant      TEXT NOT NULL DEFAULT 'default',
				hardware_id BYTEA NOT NULL CHECK(octet_length(hardware_id) = 32),
				reason      TEXT NOT NULL,
				banned_at   TIMESTAMPTZ NOT NULL,
				banned_by   TEXT NOT NULL DEFAULT '',
				note        TEXT NOT NULL DEFAULT '',
				PRIMARY KEY (tenant, hardware_id)
			);

			CREATE TABLE audit_log (
				id        BIGSERIAL PRIMARY KEY,
				timestamp TIMESTAMPTZ NOT NULL,
				action    TEXT NOT NULL,
				target_id TEXT NOT NULL,
				reason    TEXT NOT NULL DEFAULT '',
				actor     TEXT NOT NULL DEFAULT '',
				note      TEXT NOT NULL DEFAULT '',
				tenant    TEXT NOT NULL DEFAULT 'default'
			);

			CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
			CREATE INDEX idx_audit_log_target ON audit_log(target_id);
			CREATE INDEX idx_audit_log_tenant ON audit_log(tenant);

			CREATE TABLE attestation_log (
				id          BIGSERIAL PRIMARY KEY,
				timestamp   TIMESTAMPTZ NOT NULL,
				client_id   TEXT NOT NULL,
				hardware_id TEXT NOT NULL DEFAULT '',
				result      TEXT NOT NULL,
				duration_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
				pcr14       TEXT NOT NULL DEFAULT '',
				details     TEXT NOT NULL DEFAULT '',
				remote_addr TEXT NOT NULL DEFAULT '',
				tenant      TEXT NOT NULL DEFAULT 'default',
				kernel_hash TEXT NOT NULL DEFAULT '',

				-- identical trusted rounds extend one row;
				-- timestamp is its first, last_seen its last
				last_seen   TIMESTAMPTZ NOT NULL,
				rounds      BIGINT NOT NULL DEFAULT 1
			);

			CREATE INDEX idx_attestation_log_timestamp ON attestation_log(timestamp);
			CREATE INDEX idx_attestation_log_client ON attestation_log(client_id);
			CREATE INDEX idx_attestation_log_result ON attestation_log(result);
			CREATE INDEX idx_attestation_log_tenant ON attestation_log(tenant);

			-- newest row per tenant and client, read by every record
			CREATE INDEX idx_attestation_log_standing
				ON attestation_log(tenant, client_id, id DESC);

			CREATE TABLE baseline_archive (
				id           BIGSERIAL PRIMARY KEY,
				client_id    TEXT NOT NULL,
				archived_at  TIMESTAMPTZ NOT NULL,
				pcr0         BYTEA,
				pcr1         BYTEA,
				pcr7         BYTEA,
				agent_hash   BYTEA,
				esrt_version BIGINT,
				reason       TEXT NOT NULL DEFAULT ''
			);

			CREATE INDEX idx_baseline_archive_client ON baseline_archive(client_id);

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

// DefaultPGMaxOpenConns is the per-instance connection pool ceiling used when
// the operator does not tune it.
// Database commits concurrent transactions in one WAL fsync (group commit),
// so the pool size caps how many enrollment/attestation writes coalesce per fsync:
// wider pool lifts burst throughput until it hits the database's max_connections
// (shared by every instance's pool).
// Keep it well under max_connections / instances.
const DefaultPGMaxOpenConns = 20

// OpenPostgresDB opens a Postgres-backed store at the given DSN with the
// default connection pool and applies pending schema migrations.
//
// DSN is a libpq/pgx connection string, e.g:
// "postgres://user:pass@host:5432/lota?sslmode=verify-full"
func OpenPostgresDB(dsn string) (*sql.DB, error) {
	return OpenPostgresDBPool(dsn, DefaultPGMaxOpenConns)
}

// ServerMaxConnections reports the database server's max_connections,
// the budget every instance's pool is drawn from.
//
// Connection pooler in front of the database may report its own backend limit
// or refuse the query outright, so callers treat an error as "unknown" and carry
// on rather than failing deployment that is fronted by one.
func ServerMaxConnections(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow("SELECT current_setting('max_connections')::int").Scan(&n); err != nil {
		return 0, fmt.Errorf("read max_connections: %w", err)
	}
	return n, nil
}

// OpenPostgresDBPool opens the backend with an explicit max-open-connections pool ceiling
// and applies pending schema migrations.
// Non-positive value falls back to DefaultPGMaxOpenConns.
//
// Pooling is left to database/sql; the pool is sized for the per-instance
// attestation concurrency, not the whole fleet, because every verifier
// instance opens its own pool against the shared server.
func OpenPostgresDBPool(dsn string, maxOpenConns int) (*sql.DB, error) {
	db, err := openPostgresPool(dsn, maxOpenConns)
	if err != nil {
		return nil, err
	}

	// name a standby before migrating it fails with a bare read-only error
	if err := refuseStandby(db); err != nil {
		db.Close()
		return nil, err
	}

	if err := runPgMigrations(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres migration failed: %w", err)
	}

	return db, nil
}

// OpenPostgresDBReadOnly opens a database for a reporting instance,
// e.g. on a hot standby, and applies no migration. The schema is verified
// as for a writer (version, fingerprint, tables) so a mismatch fails at
// startup, not at the first query. A missing fingerprint is warned about,
// not recorded.
func OpenPostgresDBReadOnly(dsn string, maxOpenConns int) (*sql.DB, error) {
	db, err := openPostgresPool(dsn, maxOpenConns)
	if err != nil {
		return nil, err
	}

	if err := verifyPgSchemaReadOnly(context.Background(), db); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// openPostgresPool opens and sizes the pool for both entry points.
func openPostgresPool(dsn string, maxOpenConns int) (*sql.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("postgres DSN is empty")
	}
	if maxOpenConns <= 0 {
		maxOpenConns = DefaultPGMaxOpenConns
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres connection: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres ping failed: %w", err)
	}

	idle := maxOpenConns / 2
	if idle < 1 {
		idle = 1
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(idle)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	return db, nil
}

// ErrSchemaAbsent: a read-only open found no LOTA schema and creates none.
var ErrSchemaAbsent = errors.New("database carries no LOTA schema")

// verifyPgSchemaReadOnly checks the schema against this build without writing.
// No advisory lock: it changes nothing, so nothing races with it.
func verifyPgSchemaReadOnly(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire a connection: %w", err)
	}
	defer conn.Close()

	var version int
	var stored sql.NullString
	err = conn.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0), MAX(fingerprint) FROM schema_version").Scan(&version, &stored)
	switch {
	case err != nil && isMissingSchemaVersion(err):
		return fmt.Errorf("%w: point this instance at a database a verifier has built, "+
			"or start one on the primary to build it", ErrSchemaAbsent)
	case err != nil:
		return fmt.Errorf("failed to read the schema version: %w", err)
	case version == 0:
		return fmt.Errorf("%w: point this instance at a database a verifier has built, "+
			"or start one on the primary to build it", ErrSchemaAbsent)
	}

	target := maxMigrationVersion(pgMigrations)
	if version > target {
		return schemaVersionError(version, target)
	}
	if version < target {
		// a writer would migrate; a reader names who must
		return fmt.Errorf("%w: the database is at schema version %d and this build reads %d; "+
			"a verifier on the primary applies the missing migrations",
			ErrSchemaShapeMismatch, version, target)
	}

	expected := schemaFingerprint(pgMigrations)
	switch {
	case !stored.Valid || stored.String == "":
		slog.Warn("reading a database that records no schema fingerprint",
			"fingerprint", shortFingerprint(expected),
			"note", "it predates fingerprinting; its shape is verified against this build's tables and left as it is")
	case stored.String != expected:
		return schemaFingerprintError(stored.String, expected)
	}

	tables, err := pgTableNames(ctx, conn)
	if err != nil {
		return err
	}
	return schemaShapeError(schemaTables(pgMigrations), tables)
}

// isMissingSchemaVersion reports undefined_table (42P01):
// no verifier built this database.
func isMissingSchemaVersion(err error) bool {
	return strings.Contains(err.Error(), "42P01") ||
		strings.Contains(strings.ToLower(err.Error()), "does not exist")
}

// ErrDatabaseInRecovery is returned when the DSN points at a hot standby,
// which cannot take the startup migration.
var ErrDatabaseInRecovery = errors.New("database is a read-only standby")

// refuseStandby returns ErrDatabaseInRecovery on a standby.
// If pg_is_in_recovery() fails, the check is skipped and the migration decides.
func refuseStandby(db *sql.DB) error {
	var inRecovery bool
	if err := db.QueryRow("SELECT pg_is_in_recovery()").Scan(&inRecovery); err != nil {
		return nil
	}
	if !inRecovery {
		return nil
	}
	return fmt.Errorf("%w: a verifier applies its schema at startup and needs the primary; "+
		"point this instance at the writable database and leave the replica to reporting tools that read it directly",
		ErrDatabaseInRecovery)
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

	if _, err := conn.ExecContext(ctx,
		"ALTER TABLE schema_version ADD COLUMN IF NOT EXISTS fingerprint TEXT"); err != nil {
		return fmt.Errorf("failed to add the schema fingerprint column: %w", err)
	}

	var current int
	if err := conn.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current); err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	// refuse a version this build never applied: a newer build wrote it
	if target := maxMigrationVersion(pgMigrations); current > target {
		return schemaVersionError(current, target)
	}

	existing := current > 0

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

	return verifyPgSchemaIdentity(ctx, conn, existing)
}

// verifyPgSchemaIdentity is verifySQLiteSchemaIdentity for Postgres.
// Runs under the migration advisory lock, so concurrent starts agree.
func verifyPgSchemaIdentity(ctx context.Context, conn *sql.Conn, existing bool) error {
	expected := schemaFingerprint(pgMigrations)

	var stored sql.NullString
	err := conn.QueryRowContext(ctx,
		"SELECT fingerprint FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to read the schema fingerprint: %w", err)
	}

	switch {
	case !stored.Valid || stored.String == "":
		if _, err := conn.ExecContext(ctx,
			"UPDATE schema_version SET fingerprint = $1 WHERE version = (SELECT MAX(version) FROM schema_version)",
			expected); err != nil {
			return fmt.Errorf("failed to record the schema fingerprint: %w", err)
		}
		if existing {
			slog.Warn("recorded a schema fingerprint for a database that carried none",
				"fingerprint", shortFingerprint(expected),
				"note", "the database predates fingerprinting; its shape is verified against this build's tables")
		}
	case stored.String != expected:
		return schemaFingerprintError(stored.String, expected)
	}

	tables, err := pgTableNames(ctx, conn)
	if err != nil {
		return err
	}
	return schemaShapeError(schemaTables(pgMigrations), tables)
}

// pgTableNames lists the tables in the connection's current schema,
// excluding schema_version.
func pgTableNames(ctx context.Context, conn *sql.Conn) ([]string, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema()
		  AND table_type = 'BASE TABLE'
		  AND table_name <> 'schema_version'`)
	if err != nil {
		return nil, fmt.Errorf("failed to list the database's tables: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to list the database's tables: %w", err)
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
