// SPDX-License-Identifier: MIT
// LOTA Verifier - PostgreSQL AIK Store
//
// Postgres counterpart of SQLiteAIKStore.
// Same semantics and TOFU invariants, only SQL dialect differs
// (numbered $N placeholders, BYTEA columns).
//
// Global AIK uniqueness is enforced by the idx_clients_aik_der_unique index,
// with a pre-check SELECT kept for a friendly error that names the colliding client

package store

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PostgresAIKStore implements AIKStore against a shared Postgres database
type PostgresAIKStore struct {
	db *sql.DB
}

// NewPostgresAIKStore creates an AIK store backed by the given Postgres database
func NewPostgresAIKStore(db *sql.DB) *PostgresAIKStore {
	return &PostgresAIKStore{db: db}
}

func (s *PostgresAIKStore) GetAIK(clientID string) (*rsa.PublicKey, error) {
	var aikDER []byte
	err := s.db.QueryRow(
		"SELECT aik_der FROM clients WHERE id = $1", clientID,
	).Scan(&aikDER)

	if err == sql.ErrNoRows {
		return nil, ErrAIKNotFound
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

func (s *PostgresAIKStore) RegisterAIK(clientID string, pubKey *rsa.PublicKey) error {
	// check if already registered
	var existingDER []byte
	err := s.db.QueryRow(
		"SELECT aik_der FROM clients WHERE id = $1", clientID,
	).Scan(&existingDER)

	if err == nil {
		// client exists - verify same key (TOFU invariant)
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
		"SELECT id FROM clients WHERE aik_der = $1 LIMIT 1", derBytes,
	).Scan(&duplicateClientID)
	if err == nil {
		return fmt.Errorf("%w: %s", ErrAIKAlreadyRegistered, duplicateClientID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check global AIK uniqueness: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT INTO clients (id, aik_der) VALUES ($1, $2)",
		clientID, derBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to store AIK: %w", err)
	}

	return nil
}

// RegisterAIKWithCert falls back to TOFU
// (no certificate verification at storage layer)
func (s *PostgresAIKStore) RegisterAIKWithCert(clientID string, pubKey *rsa.PublicKey, aikCert, ekCert []byte) error {
	return s.RegisterAIK(clientID, pubKey)
}

// RegisterHardwareID stores or validates hardware identity (TOFU binding)
func (s *PostgresAIKStore) RegisterHardwareID(clientID string, hardwareID [32]byte) error {
	var existing []byte
	err := s.db.QueryRow(
		"SELECT hardware_id FROM clients WHERE id = $1", clientID,
	).Scan(&existing)

	if err == sql.ErrNoRows {
		return ErrAIKNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to query hardware ID: %w", err)
	}

	if len(existing) == 32 {
		var stored [32]byte
		copy(stored[:], existing)
		if stored != hardwareID {
			return ErrHardwareIDMismatch
		}
		return nil // same hardware, all good
	}

	// store new hardware ID
	_, err = s.db.Exec(
		"UPDATE clients SET hardware_id = $1 WHERE id = $2",
		hardwareID[:], clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to store hardware ID: %w", err)
	}

	return nil
}

func (s *PostgresAIKStore) GetHardwareID(clientID string) ([32]byte, error) {
	var hwid []byte
	err := s.db.QueryRow(
		"SELECT hardware_id FROM clients WHERE id = $1", clientID,
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

func (s *PostgresAIKStore) ListClients() []string {
	return s.ListClientsPage(0, 0)
}

func (s *PostgresAIKStore) ListClientsPage(limit, offset int) []string {
	clients, err := s.ListClientsPageE(limit, offset)
	if err != nil {
		return nil
	}
	return clients
}

func (s *PostgresAIKStore) ListClientsPageE(limit, offset int) ([]string, error) {
	query := "SELECT id FROM clients ORDER BY id"
	args := make([]any, 0, 2)

	if limit > 0 {
		args = append(args, limit)
		query += " LIMIT $" + strconv.Itoa(len(args))
		if offset > 0 {
			args = append(args, offset)
			query += " OFFSET $" + strconv.Itoa(len(args))
		}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			clients = append(clients, id)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return clients, nil
}

func (s *PostgresAIKStore) CountClients() int {
	total, err := s.CountClientsE()
	if err != nil {
		return 0
	}
	return total
}

func (s *PostgresAIKStore) CountClientsE() (int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *PostgresAIKStore) HasClient(clientID string) (bool, error) {
	var dummy int
	err := s.db.QueryRow("SELECT 1 FROM clients WHERE id = $1 LIMIT 1", clientID).Scan(&dummy)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *PostgresAIKStore) ExistingClients(clientIDs []string) (map[string]struct{}, error) {
	existing := make(map[string]struct{})
	if len(clientIDs) == 0 {
		return existing, nil
	}

	unique := make(map[string]struct{}, len(clientIDs))
	ids := make([]string, 0, len(clientIDs))
	for _, id := range clientIDs {
		if _, seen := unique[id]; seen {
			continue
		}
		unique[id] = struct{}{}
		ids = append(ids, id)
	}

	const chunkSize = 500
	for i := 0; i < len(ids); i += chunkSize {
		end := i + chunkSize
		if end > len(ids) {
			end = len(ids)
		}

		chunk := ids[i:end]
		placeholders := make([]string, len(chunk))
		args := make([]any, len(chunk))
		for j, id := range chunk {
			placeholders[j] = "$" + strconv.Itoa(j+1)
			args[j] = id
		}

		// #nosec G202 -- placeholders are generated as numbered parameters
		// and all client IDs are still passed separately through args
		query := "SELECT id FROM clients WHERE id IN (" + strings.Join(placeholders, ",") + ")"
		rows, err := s.db.Query(query, args...)
		if err != nil {
			return nil, err
		}

		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			existing[id] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	return existing, nil
}

func (s *PostgresAIKStore) GetRegisteredAt(clientID string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(
		"SELECT created_at FROM clients WHERE id = $1", clientID,
	).Scan(&t)

	if err == sql.ErrNoRows {
		return time.Time{}, errors.New("client not found")
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to query registration time: %w", err)
	}

	return t, nil
}

// RotateAIK replaces expired AIK with a new key, preserving hardware ID binding
func (s *PostgresAIKStore) RotateAIK(clientID string, newKey *rsa.PublicKey) error {
	derBytes, err := x509.MarshalPKIXPublicKey(newKey)
	if err != nil {
		return fmt.Errorf("failed to encode new key: %w", err)
	}

	var duplicateClientID string
	err = s.db.QueryRow(
		"SELECT id FROM clients WHERE aik_der = $1 AND id <> $2 LIMIT 1", derBytes, clientID,
	).Scan(&duplicateClientID)
	if err == nil {
		return fmt.Errorf("%w: %s", ErrAIKAlreadyRegistered, duplicateClientID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("failed to check global AIK uniqueness on rotation: %w", err)
	}

	result, err := s.db.Exec(
		"UPDATE clients SET aik_der = $1, created_at = CURRENT_TIMESTAMP WHERE id = $2",
		derBytes, clientID,
	)
	if err != nil {
		return fmt.Errorf("failed to rotate AIK: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read affected rows after AIK rotation: %w", err)
	}
	if rows == 0 {
		return errors.New("client not registered")
	}

	return nil
}
