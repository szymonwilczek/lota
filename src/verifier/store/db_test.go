// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Database Tests
//
// Tests for schema migration system and database lifecycle

package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDB_InMemory(t *testing.T) {
	t.Log("TEST: Opening in-memory SQLite database")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:) failed: %v", err)
	}
	defer db.Close()

	version, err := SchemaVersion(db)
	if err != nil {
		t.Fatalf("SchemaVersion failed: %v", err)
	}

	expectedVersion := len(migrations)
	if version != expectedVersion {
		t.Errorf("Schema version: got %d, want %d", version, expectedVersion)
	}

	t.Logf("✓ In-memory database opened with schema v%d", expectedVersion)
}

func TestOpenDB_FileSystem(t *testing.T) {
	t.Log("TEST: Opening file-based SQLite database")

	tmpDir, err := os.MkdirTemp("", "lota-db-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "lota.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB(%s) failed: %v", dbPath, err)
	}
	db.Close()

	// verify file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// should succeed without re-running migrations
	db2, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("Reopening database failed: %v", err)
	}
	defer db2.Close()

	version, _ := SchemaVersion(db2)
	expectedVersion := len(migrations)
	if version != expectedVersion {
		t.Errorf("Schema version after reopen: got %d, want %d", version, expectedVersion)
	}

	t.Log("✓ File-based database created and reopened successfully")
}

func TestMigrations_Idempotent(t *testing.T) {
	t.Log("TEST: Migration idempotency")
	t.Log("Running migrations twice should not fail")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// run migrations again manually
	if err := runMigrations(db); err != nil {
		t.Fatalf("Second migration run failed: %v", err)
	}

	version, _ := SchemaVersion(db)
	expectedVersion := len(migrations)
	if version != expectedVersion {
		t.Errorf("Schema version after double migration: got %d, want %d", version, expectedVersion)
	}

	t.Log("✓ Migrations are idempotent")
}

func TestMigrations_TablesExist(t *testing.T) {
	t.Log("TEST: Verifying all expected tables exist after migration")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	expectedTables := []string{"schema_version", "clients", "baselines", "used_nonces", "revocations", "hardware_bans", "audit_log"}

	for _, table := range expectedTables {
		t.Run(table, func(t *testing.T) {
			var name string
			err := db.QueryRow(
				"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
			).Scan(&name)
			if err == sql.ErrNoRows {
				t.Errorf("Table %s does not exist", table)
			} else if err != nil {
				t.Errorf("Failed to check table %s: %v", table, err)
			}
		})
	}

	t.Log("✓ All expected tables exist")
}

func TestMigrations_IndexExists(t *testing.T) {
	t.Log("TEST: Verifying used_nonces index exists")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	var name string
	err = db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='index' AND name='idx_used_nonces_used_at'",
	).Scan(&name)
	if err != nil {
		t.Errorf("Index idx_used_nonces_used_at not found: %v", err)
	}

	t.Log("✓ used_nonces index exists for efficient cleanup")
}

func TestMigrations_PCR14Constraint(t *testing.T) {
	t.Log("SECURITY TEST: PCR14 BLOB length constraint")
	t.Log("Must reject baselines with invalid PCR14 size")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// invalid PCR14 (wrong length)
	_, err = db.Exec(
		"INSERT INTO baselines (client_id, pcr14, first_seen, last_seen) VALUES (?, ?, datetime('now'), datetime('now'))",
		"test-client", []byte("too-short"),
	)
	if err == nil {
		t.Fatal("SECURITY: Accepted PCR14 with invalid length!")
	}

	// 32-byte PCR14 should succeed
	pcr14 := make([]byte, 32)
	_, err = db.Exec(
		"INSERT INTO baselines (client_id, pcr14, first_seen, last_seen) VALUES (?, ?, datetime('now'), datetime('now'))",
		"test-client", pcr14,
	)
	if err != nil {
		t.Errorf("Failed to insert valid PCR14: %v", err)
	}

	t.Log("✓ PCR14 length constraint enforced at database level")
}

func TestOpenDB_WALMode(t *testing.T) {
	t.Log("TEST: WAL journal mode for concurrent reads")

	tmpDir, err := os.MkdirTemp("", "lota-wal-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "wal-test.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	var journalMode string
	db.QueryRow("PRAGMA journal_mode").Scan(&journalMode)

	if journalMode != "wal" {
		t.Errorf("Journal mode: got %s, want wal", journalMode)
	}

	t.Logf("✓ WAL mode active: %s", journalMode)
}
