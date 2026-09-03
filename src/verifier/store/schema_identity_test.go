// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what identifies the schema a database holds

package store

import (
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
