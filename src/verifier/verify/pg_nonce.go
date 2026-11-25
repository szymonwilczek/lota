// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL Used Nonce Backend

package verify

import (
	"database/sql"
	"errors"
	"time"
)

// PostgresUsedNonceBackend keeps the used-nonce history in Postgres,
// so instances sharing the database refuse each other's used nonces.
type PostgresUsedNonceBackend struct {
	db *sql.DB
}

// NewPostgresUsedNonceBackend returns a backend over db.
func NewPostgresUsedNonceBackend(db *sql.DB) *PostgresUsedNonceBackend {
	return &PostgresUsedNonceBackend{db: db}
}

func (s *PostgresUsedNonceBackend) Record(nonceKey string, usedAt time.Time) error {
	hash := hexEncode(nonceKey)
	_, err := s.db.Exec(
		"INSERT INTO used_nonces (nonce_hash, used_at) VALUES ($1, $2) ON CONFLICT (nonce_hash) DO NOTHING",
		hash, usedAt.UTC(),
	)
	return err
}

// Contains returns an error, not false, when the database cannot answer.
func (s *PostgresUsedNonceBackend) Contains(nonceKey string) (bool, error) {
	hash := hexEncode(nonceKey)
	var exists int
	err := s.db.QueryRow(
		"SELECT 1 FROM used_nonces WHERE nonce_hash = $1", hash,
	).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *PostgresUsedNonceBackend) Count() int {
	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM used_nonces").Scan(&count); err != nil {
		return 0
	}
	return count
}

func (s *PostgresUsedNonceBackend) Cleanup(olderThan time.Time) {
	if _, err := s.db.Exec("DELETE FROM used_nonces WHERE used_at < $1", olderThan.UTC()); err != nil {
		return
	}
}
