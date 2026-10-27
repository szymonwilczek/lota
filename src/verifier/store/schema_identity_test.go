// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what identifies the schema a database holds

package store

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// The consolidated migration is rewritten in place before 1.0, so the version
// number alone does not identify a schema. A database stamped with a version
// newer than this build knows must be refused at open.
func TestOpenDBRefusesADatabaseWrittenByANewerBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.sqlite")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}

	// a schema this build has never heard of, as a later build would leave it
	if _, err := db.Exec("INSERT INTO schema_version (version) VALUES (?)",
		SQLiteTargetSchemaVersion()+1); err != nil {
		t.Fatalf("stamp a newer version: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenDB(path)
	if err == nil {
		reopened.Close()
		t.Fatal("a database written by a newer build must be refused, not served")
	}
	msg := err.Error()
	for _, want := range []string{"schema"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q: %s", want, msg)
		}
	}
}

// Same version, different shape: a table this build did not create must be
// refused and named at open, not left to fail on first use.
func TestOpenDBRefusesAShapeThisBuildDidNotWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shape.sqlite")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}

	// a table another build of this same schema version created
	if _, err := db.Exec(`CREATE TABLE session_tokens (
		token_hash BLOB PRIMARY KEY,
		consumed   INTEGER NOT NULL DEFAULT 0
	)`); err != nil {
		t.Fatalf("create the other build's table: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenDB(path)
	if err == nil {
		reopened.Close()
		t.Fatal("a database whose shape this build did not write must be refused")
	}
	if !strings.Contains(err.Error(), "session_tokens") {
		t.Errorf("the refusal must name what differs, got: %s", err.Error())
	}
}

// The fingerprint must change when any migration's SQL does.
func TestSchemaFingerprintMovesWithTheSQL(t *testing.T) {
	base := []migration{{version: 1, description: "one", sql: "CREATE TABLE a (id TEXT);"}}
	sameShape := []migration{{version: 1, description: "one", sql: "CREATE TABLE a (id TEXT);"}}
	changedSQL := []migration{{version: 1, description: "one", sql: "CREATE TABLE a (id TEXT, extra TEXT);"}}
	changedText := []migration{{version: 1, description: "one, reworded", sql: "CREATE TABLE a (id TEXT);"}}

	if schemaFingerprint(base) != schemaFingerprint(sameShape) {
		t.Fatal("the same migrations must fingerprint the same way")
	}
	if schemaFingerprint(base) == schemaFingerprint(changedSQL) {
		t.Fatal("a column added to the migration must move the fingerprint")
	}
	if schemaFingerprint(base) == schemaFingerprint(changedText) {
		t.Fatal("a reworded description must move the fingerprint: it is what the log line reports")
	}
}

// The expected tables are parsed out of the migrations.
func TestSchemaTablesComeFromTheMigrations(t *testing.T) {
	got := schemaTables([]migration{
		{sql: "CREATE TABLE clients (id TEXT); CREATE UNIQUE INDEX idx ON clients(id);"},
		{sql: "CREATE TABLE IF NOT EXISTS Bans (id TEXT);"},
	})
	want := []string{"bans", "clients"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("schemaTables = %v, want %v", got, want)
	}

	// and the live schema is held to them
	if err := schemaShapeError([]string{"clients"}, []string{"clients", "session_tokens"}); err == nil {
		t.Fatal("a table the migrations do not create must be reported")
	}
	if err := schemaShapeError([]string{"clients", "baselines"}, []string{"clients"}); err == nil {
		t.Fatal("a table the migrations create and the database lacks must be reported")
	}
	if err := schemaShapeError([]string{"clients"}, []string{"CLIENTS"}); err != nil {
		t.Fatalf("table names differing only in case must agree: %v", err)
	}
}

// A foreign fingerprint is refused even when the tables match:
// the difference may be a column.
func TestOpenDBRefusesAnotherBuildsFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.sqlite")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	if _, err := db.Exec("UPDATE schema_version SET fingerprint = ?",
		"0000000000000000000000000000000000000000000000000000000000000000"); err != nil {
		t.Fatalf("stamp another build's fingerprint: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := OpenDB(path)
	if err == nil {
		reopened.Close()
		t.Fatal("a database written by a build with different migrations must be refused")
	}
	if !errors.Is(err, ErrSchemaFingerprintMismatch) {
		t.Fatalf("refusal = %v, want ErrSchemaFingerprintMismatch", err)
	}
	if !strings.Contains(err.Error(), "000000000000") {
		t.Fatalf("the refusal must name what it found: %s", err.Error())
	}
}

// A database this build wrote reopens without migrating.
func TestOpenDBReopensItsOwnDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "own.sqlite")

	db, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	version, err := SchemaVersion(db)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	again, err := OpenDB(path)
	if err != nil {
		t.Fatalf("reopening its own database must work: %v", err)
	}
	defer again.Close()

	reopenedVersion, err := SchemaVersion(again)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if reopenedVersion != version {
		t.Fatalf("schema version moved on reopen: %d -> %d", version, reopenedVersion)
	}
}
