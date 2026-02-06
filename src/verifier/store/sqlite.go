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
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
)

// implements AIKStore using a SQLite database
// provides persistence across verifier restarts without filesystem overhead
type SQLiteAIKStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// creates an AIK store backed by the given database
func NewSQLiteAIKStore(db *sql.DB) *SQLiteAIKStore {
	return &SQLiteAIKStore{db: db}
}

func (s *SQLiteAIKStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var aikPEM string
	err := s.db.QueryRow(
		"SELECT aik_pem FROM clients WHERE id = ?", clientID,
	).Scan(&aikPEM)

	if err == sql.ErrNoRows {
		return nil, errors.New("AIK not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query AIK: %w", err)
	}

	return decodePEMPublicKey(aikPEM)
}

func (s *SQLiteAIKStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// check if already registered
	var existingPEM string
	err := s.db.QueryRow(
		"SELECT aik_pem FROM clients WHERE id = ?", clientID,
	).Scan(&existingPEM)

	if err == nil {
		// client exists — verify same key (TOFU invariant)
		existingKey, parseErr := decodePEMPublicKey(existingPEM)
		if parseErr != nil {
			return fmt.Errorf("corrupt stored key: %w", parseErr)
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
	pemText, err := encodePEMPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT INTO clients (id, aik_pem) VALUES (?, ?)",
		clientID, pemText,
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
	s.mu.Lock()
	defer s.mu.Unlock()

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
	s.mu.RLock()
	defer s.mu.RUnlock()

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

func (s *SQLiteAIKStore) RevokeAIK(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// also remove associated baseline
	_, err := s.db.Exec("DELETE FROM clients WHERE id = ?", clientID)
	if err != nil {
		return fmt.Errorf("failed to revoke AIK: %w", err)
	}

	return nil
}

func (s *SQLiteAIKStore) ListClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

// marshals an RSA public key to PEM text
func encodePEMPublicKey(pubKey *rsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// parses PEM text back to an RSA public key
func decodePEMPublicKey(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}
