// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite AIK Store
//
// Persistent Attestation Identity Key storage backed by SQLite.
// Stores public keys as PEM text in the clients table and
// hardware IDs as raw BLOBs for TOFU identity binding.

package store

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// implements AIKStore using a SQLite database
// provides persistence across verifier restarts without filesystem overhead
type SQLiteAIKStore struct {
	db *sql.DB
}

// creates an AIK store backed by the given database
func NewSQLiteAIKStore(db *sql.DB) *SQLiteAIKStore {
	return &SQLiteAIKStore{db: db}
}

func (s *SQLiteAIKStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	var aikDER []byte
	err := s.db.QueryRow(
		"SELECT aik_der FROM clients WHERE id = ?", clientID,
	).Scan(&aikDER)

	if err == sql.ErrNoRows {
		return nil, errors.New("AIK not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query AIK: %w", err)
	}

	pub, err := x509.ParsePKIXPublicKey(aikDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

func (s *SQLiteAIKStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	// check if already registered
	var existingDER []byte
	err := s.db.QueryRow(
		"SELECT aik_der FROM clients WHERE id = ?", clientID,
	).Scan(&existingDER)

	if err == nil {
		// client exists — verify same key (TOFU invariant)
		pub, parseErr := x509.ParsePKIXPublicKey(existingDER)
		if parseErr != nil {
			return fmt.Errorf("corrupt stored key: %w", parseErr)
		}

		existingKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("stored key is not an RSA public key")
		}

		if !publicKeysEqual(existingKey, pubKey) {
			return errors.New("client already registered with different key")
		}
		return nil // same key, idempotent
	}

	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check existing AIK: %w", err)
	}

	// encode and insert new client
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	var duplicateClientID string
	err = s.db.QueryRow(
		"SELECT id FROM clients WHERE aik_der = ? LIMIT 1", derBytes,
	).Scan(&duplicateClientID)
	if err == nil {
		return fmt.Errorf("%w: %s", ErrAIKAlreadyRegistered, duplicateClientID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check global AIK uniqueness: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT INTO clients (id, aik_der) VALUES (?, ?)",
		clientID, derBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to store AIK: %w", err)
	}

	return nil
}

// falls back to TOFU (no certificate verification at storage layer)
func (s *SQLiteAIKStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error {
	return s.RegisterAIK(clientID, pubKey)
}

// stores or validates hardware identity (TOFU binding)
func (s *SQLiteAIKStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	var existing []byte
	err := s.db.QueryRow(
		"SELECT hardware_id FROM clients WHERE id = ?", clientID,
	).Scan(&existing)

	if err == sql.ErrNoRows {
		return errors.New("AIK not found")
	}
	if err != nil {
		return fmt.Errorf("failed to query hardware ID: %w", err)
	}

	if existing != nil && len(existing) == 32 {
		var stored [32]byte
		copy(stored[:], existing)
		if stored != hardwareID {
			return ErrHardwareIDMismatch
		}
		return nil // same hardware, all good
	}

	// store new hardware ID
	_, err = s.db.Exec(
		"UPDATE clients SET hardware_id = ? WHERE id = ?",
		hardwareID[:], clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to store hardware ID: %w", err)
	}

	return nil
}

func (s *SQLiteAIKStore) GetHardwareID(clientID string) ([32]byte, error) {
	var hwid []byte
	err := s.db.QueryRow(
		"SELECT hardware_id FROM clients WHERE id = ?", clientID,
	).Scan(&hwid)

	if err == sql.ErrNoRows || hwid == nil {
		return [32]byte{}, ErrHardwareIDNotFound
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to query hardware ID: %w", err)
	}

	if len(hwid) != 32 {
		return [32]byte{}, fmt.Errorf("corrupt hardware ID: expected 32 bytes, got %d", len(hwid))
	}

	var result [32]byte
	copy(result[:], hwid)
	return result, nil
}

func (s *SQLiteAIKStore) ListClients() []string {
	rows, err := s.db.Query("SELECT id FROM clients ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var clients []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			clients = append(clients, id)
		}
	}

	return clients
}

func (s *SQLiteAIKStore) GetRegisteredAt(clientID string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(
		"SELECT created_at FROM clients WHERE id = ?", clientID,
	).Scan(&t)

	if err == sql.ErrNoRows {
		return time.Time{}, errors.New("client not found")
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query registration time: %w", err)
	}

	return t, nil
}

// replaces expired AIK with a new key, preserving hardware ID binding
func (s *SQLiteAIKStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	derBytes, err := x509.MarshalPKIXPublicKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to encode new key: %w", err)
	}

	var duplicateClientID string
	err = s.db.QueryRow(
		"SELECT id FROM clients WHERE aik_der = ? AND id <> ? LIMIT 1", derBytes, clientID,
	).Scan(&duplicateClientID)
	if err == nil {
		return fmt.Errorf("%w: %s", ErrAIKAlreadyRegistered, duplicateClientID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check global AIK uniqueness on rotation: %w", err)
	}

	result, err := s.db.Exec(
		"UPDATE clients SET aik_der = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?",
		derBytes, clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to rotate AIK: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("client not registered")
	}

	return nil
}
