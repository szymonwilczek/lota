// SPDX-License-Identifier: MIT
// LOTA Verifier - PostgreSQL Revocation, Ban, and Audit Log Stores
//
// Postgres counterparts of the SQLite revocation, ban, audit and
// attestation stores. Same semantics and the same append-only audit
// trail; only the SQL dialect differs (numbered $N placeholders, BYTEA
// hardware IDs).
// All four share the Postgres connection opened by store.OpenPostgresDB()

package store

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// PostgresRevocationStore implements RevocationStore using
// the revocations table
type PostgresRevocationStore struct {
	mu       sync.RWMutex
	db       *sql.DB
	auditLog AuditLog
}

// NewPostgresRevocationStore creates a revocation store backed by
// the given Postgres database if auditLog is non-nil,
// all actions are recorded in the audit trail
func NewPostgresRevocationStore(db *sql.DB, auditLog AuditLog) *PostgresRevocationStore {
	return &PostgresRevocationStore{db: db, auditLog: auditLog}
}

func (s *PostgresRevocationStore) Revoke(clientID string, reason RevocationReason, revokedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var existing string
	err := s.db.QueryRow("SELECT client_id FROM revocations WHERE client_id = $1", clientID).Scan(&existing)
	if err == nil {
		return ErrAlreadyRevoked
	}
	if err != sql.ErrNoRows {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		"INSERT INTO revocations (client_id, reason, revoked_at, revoked_by, note) VALUES ($1, $2, $3, $4, $5)",
		clientID, string(reason), now, revokedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log("revoke", clientID, string(reason), revokedBy, note); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresRevocationStore) IsRevoked(clientID string) (*RevocationEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entry RevocationEntry
	var reason string
	err := s.db.QueryRow(
		"SELECT client_id, reason, revoked_at, revoked_by, note FROM revocations WHERE client_id = $1",
		clientID,
	).Scan(&entry.ClientID, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note)
	if err != nil {
		return nil, false
	}

	entry.Reason = RevocationReason(reason)
	return &entry, true
}

func (s *PostgresRevocationStore) Unrevoke(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM revocations WHERE client_id = $1", clientID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read affected rows after unrevoke: %w", err)
	}
	if rows == 0 {
		return ErrNotRevoked
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log("unrevoke", clientID, "", "", ""); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresRevocationStore) ListRevocations() []RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT client_id, reason, revoked_at, revoked_by, note FROM revocations ORDER BY revoked_at DESC",
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []RevocationEntry
	for rows.Next() {
		var entry RevocationEntry
		var reason string
		if err := rows.Scan(&entry.ClientID, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note); err == nil {
			entry.Reason = RevocationReason(reason)
			entries = append(entries, entry)
		}
	}
	return entries
}

// PostgresBanStore implements BanStore using the hardware_bans table
type PostgresBanStore struct {
	db       *sql.DB
	auditLog AuditLog
}

// NewPostgresBanStore creates a ban store backed by the given Postgres
// database if auditLog is non-nil,
// all actions are recorded in the audit trail
func NewPostgresBanStore(db *sql.DB, auditLog AuditLog) *PostgresBanStore {
	return &PostgresBanStore{db: db, auditLog: auditLog}
}

func (s *PostgresBanStore) BanHardware(hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error {
	var existing []byte
	err := s.db.QueryRow("SELECT hardware_id FROM hardware_bans WHERE hardware_id = $1", hardwareID[:]).Scan(&existing)
	if err == nil {
		return ErrAlreadyBanned
	}
	if err != sql.ErrNoRows {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		"INSERT INTO hardware_bans (hardware_id, reason, banned_at, banned_by, note) VALUES ($1, $2, $3, $4, $5)",
		hardwareID[:], string(reason), now, bannedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log("ban", FormatHardwareID(hardwareID), string(reason), bannedBy, note); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresBanStore) IsBanned(hardwareID [32]byte) (*BanEntry, bool) {
	var entry BanEntry
	var hwid []byte
	var reason string
	err := s.db.QueryRow(
		"SELECT hardware_id, reason, banned_at, banned_by, note FROM hardware_bans WHERE hardware_id = $1",
		hardwareID[:],
	).Scan(&hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note)
	if err != nil {
		return nil, false
	}

	if len(hwid) == 32 {
		copy(entry.HardwareID[:], hwid)
	}
	entry.Reason = RevocationReason(reason)
	return &entry, true
}

func (s *PostgresBanStore) UnbanHardware(hardwareID [32]byte) error {
	result, err := s.db.Exec("DELETE FROM hardware_bans WHERE hardware_id = $1", hardwareID[:])
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read affected rows after hardware unban: %w", err)
	}
	if rows == 0 {
		return ErrNotBanned
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log("unban", FormatHardwareID(hardwareID), "", "", ""); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresBanStore) ListBans() []BanEntry {
	return s.ListBansPage(0, 0)
}

func (s *PostgresBanStore) ListBansPage(limit, offset int) []BanEntry {
	entries, err := s.ListBansPageE(limit, offset)
	if err != nil {
		return nil
	}
	return entries
}

func (s *PostgresBanStore) ListBansPageE(limit, offset int) ([]BanEntry, error) {
	query := "SELECT hardware_id, reason, banned_at, banned_by, note FROM hardware_bans ORDER BY banned_at DESC"
	args := make([]any, 0, 2)
	if limit > 0 {
		// args is empty here, so limit is always $1 and offset $2
		args = append(args, limit)
		query += " LIMIT $1"
		if offset > 0 {
			args = append(args, offset)
			query += " OFFSET $2"
		}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []BanEntry
	for rows.Next() {
		var entry BanEntry
		var hwid []byte
		var reason string
		if err := rows.Scan(&hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note); err == nil {
			if len(hwid) == 32 {
				copy(entry.HardwareID[:], hwid)
			}
			entry.Reason = RevocationReason(reason)
			entries = append(entries, entry)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func (s *PostgresBanStore) ListBansAfter(limit int, nextID string) ([]BanEntry, error) {
	if limit <= 0 {
		return []BanEntry{}, nil
	}

	query := "SELECT hardware_id, reason, banned_at, banned_by, note FROM hardware_bans"
	args := make([]any, 0, 4)

	if nextID != "" {
		cursor, err := DecodeBanCursor(nextID)
		if err != nil {
			return nil, err
		}
		query += " WHERE (banned_at < $1) OR (banned_at = $2 AND hardware_id < $3)" +
			" ORDER BY banned_at DESC, hardware_id DESC LIMIT $4"
		args = append(args, cursor.BannedAt, cursor.BannedAt, cursor.HardwareID[:], limit)
	} else {
		query += " ORDER BY banned_at DESC, hardware_id DESC LIMIT $1"
		args = append(args, limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]BanEntry, 0, limit)
	for rows.Next() {
		var entry BanEntry
		var hwid []byte
		var reason string
		if err := rows.Scan(&hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note); err == nil {
			if len(hwid) == 32 {
				copy(entry.HardwareID[:], hwid)
			}
			entry.Reason = RevocationReason(reason)
			entries = append(entries, entry)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func (s *PostgresBanStore) CountBans() int {
	total, err := s.CountBansE()
	if err != nil {
		return 0
	}
	return total
}

func (s *PostgresBanStore) CountBansE() (int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM hardware_bans").Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// PostgresAuditLog implements AuditLog using the audit_log table
type PostgresAuditLog struct {
	mu sync.Mutex
	db *sql.DB
}

// NewPostgresAuditLog creates an audit log backed by the given
// Postgres database
func NewPostgresAuditLog(db *sql.DB) *PostgresAuditLog {
	return &PostgresAuditLog{db: db}
}

func (l *PostgresAuditLog) Log(action, targetID, reason, actor, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, err := l.db.Exec(
		"INSERT INTO audit_log (timestamp, action, target_id, reason, actor, note) VALUES ($1, $2, $3, $4, $5, $6)",
		time.Now().UTC(), action, targetID, reason, actor, note,
	)
	return err
}

func (l *PostgresAuditLog) Query(limit int) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	query := "SELECT id, timestamp, action, target_id, reason, actor, note FROM audit_log ORDER BY id DESC"
	if limit > 0 {
		query += " LIMIT $1"
	}

	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = l.db.Query(query, limit)
	} else {
		rows, err = l.db.Query(query)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.Action, &entry.TargetID, &entry.Reason, &entry.Actor, &entry.Note); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

// PostgresAttestationLog implements AttestationLog using
// the attestation_log table
type PostgresAttestationLog struct {
	mu sync.Mutex
	db *sql.DB
}

// NewPostgresAttestationLog creates an attestation log backed by
// the given Postgres database
func NewPostgresAttestationLog(db *sql.DB) *PostgresAttestationLog {
	return &PostgresAttestationLog{db: db}
}

func (l *PostgresAttestationLog) Record(entry AttestationRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	_, err := l.db.Exec(
		`INSERT INTO attestation_log
		 (timestamp, client_id, hardware_id, result, duration_ms, pcr14, details, remote_addr)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		ts, entry.ClientID, entry.HardwareID, entry.Result,
		entry.DurationMs, entry.PCR14, entry.Details, entry.RemoteAddr,
	)
	return err
}

func (l *PostgresAttestationLog) QueryAttestations(limit int) []AttestationRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	query := `SELECT id, timestamp, client_id, hardware_id, result, duration_ms, pcr14, details, remote_addr
	          FROM attestation_log ORDER BY id DESC`
	if limit > 0 {
		query += " LIMIT $1"
	}

	var rows *sql.Rows
	var err error
	if limit > 0 {
		rows, err = l.db.Query(query, limit)
	} else {
		rows, err = l.db.Query(query)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []AttestationRecord
	for rows.Next() {
		var e AttestationRecord
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ClientID, &e.HardwareID,
			&e.Result, &e.DurationMs, &e.PCR14, &e.Details, &e.RemoteAddr); err == nil {
			entries = append(entries, e)
		}
	}
	return entries
}
