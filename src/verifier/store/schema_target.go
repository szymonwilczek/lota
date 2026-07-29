// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Compiled-in schema targets
//
// SchemaVersion() reports the schema live database is already at;
// functions here report the schema given verifier binary was built to reach.
//
// The two differ only while database predates an appended migration:
// target is what runMigrations brings it up to on start.
// Operator reads both to see whether starting a binary touches the schema.
//
// SQLite and Postgres histories are versioned independently on purpose.
// Each backend's number counts its own entries, so there is deliberately no
// parity requirement between them.

package store

// PgTargetSchemaVersion returns the highest Postgres schema version this
// binary knows how to apply.
// Database already at this version needs no migration from this instance;
// one below it is migrated forward on start.
func PgTargetSchemaVersion() int {
	return maxMigrationVersion(pgMigrations)
}

// SQLiteTargetSchemaVersion returns the highest SQLite schema version this
// binary knows how to apply.
func SQLiteTargetSchemaVersion() int {
	return maxMigrationVersion(migrations)
}

// maxMigrationVersion returns the greatest version in migration history.
func maxMigrationVersion(ms []migration) int {
	highest := 0
	for _, m := range ms {
		if m.version > highest {
			highest = m.version
		}
	}
	return highest
}
