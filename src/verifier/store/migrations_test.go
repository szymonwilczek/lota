// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Schema migration invariant gate
//
// Schema history is append-only:
// shipped migration is never edited, only new entry appended, so database already
// in service reaches the current shape by applying what it is missing.
// Appended migration must also be additive.
// Live database is migrated by whichever instance starts first while the other
// instances of the fleet keep operating it, and only an additive change is invisible to them.
// These tests mechanically enforce that discipline so future destructive migration
// (DROP/RENAME/type change) fails the build.

package store

import (
	"regexp"
	"testing"
)

// destructiveDDL matches statements that would break an old reader still
// bound to the pre-migration schema:
// dropping or renaming a table/column, or retyping a column in place.
// Additive statements (CREATE TABLE, CREATE INDEX, ADD COLUMN) are intentionally not matched.
var destructiveDDL = regexp.MustCompile(`(?i)\b(DROP\s+TABLE|DROP\s+COLUMN|RENAME\s+(TABLE|COLUMN|TO)|ALTER\s+COLUMN|MODIFY\s+COLUMN|SET\s+DATA\s+TYPE)\b`)

func assertAdditiveHistory(t *testing.T, label string, ms []migration) {
	t.Helper()

	if len(ms) == 0 {
		t.Fatalf("%s: migration history is empty", label)
	}

	// versions must start at 1 and increase by exactly one with no gaps
	// or duplicates, so runMigrations applies each exactly once in order
	for i, m := range ms {
		want := i + 1
		if m.version != want {
			t.Errorf("%s: migration index %d has version %d, want %d (dense 1..N required)",
				label, i, m.version, want)
		}
		if m.description == "" {
			t.Errorf("%s: migration %d has no description", label, m.version)
		}
		if destructiveDDL.MatchString(m.sql) {
			t.Errorf("%s: migration %d (%s) contains destructive DDL; migrations "+
				"must be additive so the instances already operating the database "+
				"keep working through the change",
				label, m.version, m.description)
		}
	}
}

func TestPgMigrationsAdditive(t *testing.T) {
	assertAdditiveHistory(t, "postgres", pgMigrations)
}

func TestSQLiteMigrationsAdditive(t *testing.T) {
	assertAdditiveHistory(t, "sqlite", migrations)
}

// Compiled-in target must be the last (highest) version in the history,
// which is what live database is migrated up to on start.
func TestTargetSchemaVersions(t *testing.T) {
	if got, want := PgTargetSchemaVersion(), pgMigrations[len(pgMigrations)-1].version; got != want {
		t.Errorf("PgTargetSchemaVersion() = %d, want %d", got, want)
	}
	if got, want := SQLiteTargetSchemaVersion(), migrations[len(migrations)-1].version; got != want {
		t.Errorf("SQLiteTargetSchemaVersion() = %d, want %d", got, want)
	}
	if PgTargetSchemaVersion() < 1 || SQLiteTargetSchemaVersion() < 1 {
		t.Fatal("target schema versions must be >= 1")
	}
}
