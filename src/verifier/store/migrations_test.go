// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Schema migration invariant gate
//
// Verifier fleet upgrades by rolling new instances in against shared Postgres
// while old instances keep serving.
// That only stays safe if every migration is additive:
// an instance running the old binary must still read and write a schema a newer
// peer has already migrated forward.
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

// SQLite cannot re-key a primary key in place, only rebuild the table
// (CREATE new, copy, DROP old, RENAME).
// SQLite backend is single-node with stop-swap-start upgrade,
// so no old reader observes the rebuild.
// Each exemption is deliberate entry here; Postgres has none.
var sqliteRebuildExempt = map[int]bool{
	8: true, // hardware bans re-keyed to (tenant, hardware_id)
}

func assertAdditiveHistory(t *testing.T, label string, ms []migration, exempt map[int]bool) {
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
		if destructiveDDL.MatchString(m.sql) && !exempt[m.version] {
			t.Errorf("%s: migration %d (%s) contains destructive DDL; migrations "+
				"must be additive so a rolling upgrade keeps old readers working",
				label, m.version, m.description)
		}
	}
}

func TestPgMigrationsAdditive(t *testing.T) {
	assertAdditiveHistory(t, "postgres", pgMigrations, nil)
}

func TestSQLiteMigrationsAdditive(t *testing.T) {
	assertAdditiveHistory(t, "sqlite", migrations, sqliteRebuildExempt)
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
