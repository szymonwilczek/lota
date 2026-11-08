// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Compiled-in schema targets
//
// SchemaVersion reports the version a database is at; the functions here
// report the schema this build applies. SQLite and Postgres are versioned
// independently.

package store

// PgTargetSchemaVersion returns the highest Postgres schema version this
// binary knows how to apply.
func PgTargetSchemaVersion() int {
	return maxMigrationVersion(pgMigrations)
}

// SQLiteTargetSchemaVersion returns the highest SQLite schema version this
// binary knows how to apply.
func SQLiteTargetSchemaVersion() int {
	return maxMigrationVersion(migrations)
}

// PgSchemaFingerprint returns the short fingerprint of the Postgres
// migrations this binary applies; it tells apart two builds of one schema
// version.
func PgSchemaFingerprint() string {
	return shortFingerprint(schemaFingerprint(pgMigrations))
}

// SQLiteSchemaFingerprint is PgSchemaFingerprint for SQLite.
func SQLiteSchemaFingerprint() string {
	return shortFingerprint(schemaFingerprint(migrations))
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
