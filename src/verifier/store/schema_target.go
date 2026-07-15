// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Compiled-in schema targets
//
// SchemaVersion() reports the schema live database is already at;
// Functions here report the schema given verifier binary was built to reach.
//
// Operators compare the two across rolling upgrade:
// 	every instance must target a schema greater than or equal to the one
// 	already applied to the shared Postgres, and no instance may run against
// 	a schema newer than it understands.
//
// SQLite and Postgres histories are versioned independently on purpose:
// SQLite ships one consolidated schema for single-node deployments,
// while Postgres carries the incremental history that multi-instance fleet
// migrates through. There is deliberately no parity requirement between them.

package store

// PgTargetSchemaVersion returns the highest Postgres schema version this
// binary knows how to apply.
// Shared Postgres already at this version needs no migration from this instance;
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
