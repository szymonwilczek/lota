// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Used Nonce Backend
//
// Persistent used nonce storage backed by SQLite.
// Implements UsedNonceBackend for anti-replay protection that survives
// verifier restarts.

package verify

import (
	"database/sql"
	"encoding/hex"
	"time"
)

// implements UsedNonceBackend using a SQLite database
// provides persistent anti-replay protection across verifier restarts
type SQLiteUsedNonceBackend struct {
	db *sql.DB
}

// creates a used nonce backend backed by the given database
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

func (s *SQLiteUsedNonceBackend) Contains(nonceKey string) bool {
	hash := hexEncode(nonceKey)
	var exists int
	err := s.db.QueryRow(
		"SELECT 1 FROM used_nonces WHERE nonce_hash = ?", hash,
	).Scan(&exists)
	return err == nil
}

func (s *SQLiteUsedNonceBackend) Count() int {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM used_nonces").Scan(&count)
	return count
}

func (s *SQLiteUsedNonceBackend) Cleanup(olderThan time.Time) {
	s.db.Exec("DELETE FROM used_nonces WHERE used_at < ?", olderThan.UTC())
}

// converts raw nonce key bytes to hex string for safe DB storage
func hexEncode(nonceKey string) string {
	return hex.EncodeToString([]byte(nonceKey))
}
