// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - SQLite Used Nonce Backend

package verify

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// SQLiteUsedNonceBackend keeps the used-nonce history in SQLite, across
// verifier restarts.
type SQLiteUsedNonceBackend struct {
	db *sql.DB
}

// NewSQLiteUsedNonceBackend returns a backend over db.
func NewSQLiteUsedNonceBackend(db *sql.DB) *SQLiteUsedNonceBackend {
	return &SQLiteUsedNonceBackend{db: db}
}

func (s *SQLiteUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	hash := hexEncode(nonceKey)
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO used_nonces (nonce_hash, used_at) VALUES (?, ?)",
		hash, usedAt.UTC(),
	)
	return err
}

// Contains returns an error, not false, when the database cannot answer.
func (s *SQLiteUsedNonceBackend) Contains(nonceKey string) (bool, error) {
	hash := hexEncode(nonceKey)
	var exists int
	err := s.db.QueryRow(
		"SELECT 1 FROM used_nonces WHERE nonce_hash = ?", hash,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteUsedNonceBackend) Count() int {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM used_nonces").Scan(&count); err != nil {
		return 0
	}
	return count
}

func (s *SQLiteUsedNonceBackend) Cleanup(olderThan time.Time) {
	if _, err := s.db.Exec("DELETE FROM used_nonces WHERE used_at < ?", olderThan.UTC()); err != nil {
		return
	}
}

func hexEncode(nonceKey string) string {
	return hex.EncodeToString([]byte(nonceKey))
}
