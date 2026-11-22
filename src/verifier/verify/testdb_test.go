// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
)

func testDB(t testing.TB) *sql.DB {
	t.Helper()

	db, err := store.OpenDB(filepath.Join(t.TempDir(), "v.sqlite"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
