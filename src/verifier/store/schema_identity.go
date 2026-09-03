// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what identifies the schema a database holds
//
// The consolidated migration is rewritten in place until 1.0, so the version
// number alone does not identify a schema. Open also checks, both derived from
// the migration history:
//
//   - the fingerprint of the migration SQL, recorded in schema_version
//   - the set of tables that SQL creates, against the tables the database
//     holds; this covers databases written before fingerprints existed

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// refusals returned by a store open
var (
	ErrSchemaNewerThanBuild      = errors.New("database schema is newer than this build")
	ErrSchemaFingerprintMismatch = errors.New("database schema was written by a different build")
	ErrSchemaShapeMismatch       = errors.New("database schema is not the shape this build creates")
)

// matches CREATE TABLE in either dialect's migrations
var createTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)`)

// schemaFingerprint hashes every migration's version, description and SQL,
// in order.
func schemaFingerprint(ms []migration) string {
	h := sha256.New()
	for _, m := range ms {
		fmt.Fprintf(h, "%d\x00%s\x00%s\x00", m.version, m.description, m.sql)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// schemaTables returns the tables the migrations create, sorted.
// schema_version is created by the runner, not the migrations.
func schemaTables(ms []migration) []string {
	seen := make(map[string]struct{})
	for _, m := range ms {
		for _, match := range createTable.FindAllStringSubmatch(m.sql, -1) {
			seen[strings.ToLower(match[1])] = struct{}{}
		}
	}

	tables := make([]string, 0, len(seen))
	for name := range seen {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	return tables
}

// schemaShapeError names the missing and extra tables, or returns nil.
func schemaShapeError(expected, actual []string) error {
	have := make(map[string]struct{}, len(actual))
	for _, name := range actual {
		have[strings.ToLower(name)] = struct{}{}
	}
	want := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		want[strings.ToLower(name)] = struct{}{}
	}

	var missing, extra []string
	for name := range want {
		if _, ok := have[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range have {
		if _, ok := want[name]; !ok {
			extra = append(extra, name)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)

	// phrased about the database, which is what the operator acts on
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "does not have "+strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		parts = append(parts, "carries "+strings.Join(extra, ", ")+", which these migrations do not create")
	}
	return fmt.Errorf("%w: the database %s",
		ErrSchemaShapeMismatch, strings.Join(parts, " and it "))
}

// schemaVersionError names both versions, so the operator knows which binary
// to run.
func schemaVersionError(found, target int) error {
	return fmt.Errorf("%w: the database is at schema version %d and this build knows %d; "+
		"it was written by a newer build, so run that one or restore a backup taken at %d",
		ErrSchemaNewerThanBuild, found, target, target)
}

// schemaFingerprintError reports another build's recorded fingerprint.
func schemaFingerprintError(found, expected string) error {
	return fmt.Errorf("%w: the database records schema fingerprint %s and this build applies %s; "+
		"the two builds' migrations differ, so the tables underneath are not the ones this binary expects",
		ErrSchemaFingerprintMismatch, shortFingerprint(found), shortFingerprint(expected))
}

// shortFingerprint truncates a fingerprint for log lines and errors.
func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}
