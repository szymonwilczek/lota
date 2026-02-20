// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Revocation, Ban, and Audit Log Stores
//
// Persistent implementations of RevocationStore, BanStore, and AuditLog
// backed by SQLite. All three share the same database connection opened
// by store.OpenDB() and use tables created by migration v2.
//
// The audit log is append-only. Every revoke/unrevoke/ban/unban action
// is recorded with actor identity and timestamp for forensic review.

package store

import (
	"database/sql"
	"sync"
	"time"
)

// implements RevocationStore using the revocations table
type SQLiteRevocationStore struct {
	mu       sync.RWMutex
	db       *sql.DB
	auditLog AuditLog
}

// creates a revocation store backed by the given database
// if auditLog is non-nil, all actions are recorded in the audit trail
func NewSQLiteRevocationStore(db *sql.DB, auditLog AuditLog) *SQLiteRevocationStore {
	return &SQLiteRevocationStore{db: db, auditLog: auditLog}
}

func (s *SQLiteRevocationStore) Revoke(clientID string, reason RevocationReason, revokedBy, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// check if already revoked
	var existing string
	err := s.db.QueryRow("SELECT client_id FROM revocations WHERE client_id = ?", clientID).Scan(&existing)
	if err == nil {
		return ErrAlreadyRevoked
	}
	if err != sql.ErrNoRows {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		"INSERT INTO revocations (client_id, reason, revoked_at, revoked_by, note) VALUES (?, ?, ?, ?, ?)",
		clientID, string(reason), now, revokedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		s.auditLog.Log("revoke", clientID, string(reason), revokedBy, note)
	}

	return nil
}

func (s *SQLiteRevocationStore) IsRevoked(clientID string) (*RevocationEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entry RevocationEntry
	var reason string
	err := s.db.QueryRow(
		"SELECT client_id, reason, revoked_at, revoked_by, note FROM revocations WHERE client_id = ?",
		clientID,
	).Scan(&entry.ClientID, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note)
	if err != nil {
		return nil, false
	}

	entry.Reason = RevocationReason(reason)
	return &entry, true
}

func (s *SQLiteRevocationStore) Unrevoke(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM revocations WHERE client_id = ?", clientID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotRevoked
	}

	if s.auditLog != nil {
		s.auditLog.Log("unrevoke", clientID, "", "", "")
	}

	return nil
}

func (s *SQLiteRevocationStore) ListRevocations() []RevocationEntry {
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

// implements BanStore using the hardware_bans table
type SQLiteBanStore struct {
	db       *sql.DB
	auditLog AuditLog
}

// creates a ban store backed by the given database
// if auditLog is non-nil, all actions are recorded in the audit trail
func NewSQLiteBanStore(db *sql.DB, auditLog AuditLog) *SQLiteBanStore {
	return &SQLiteBanStore{db: db, auditLog: auditLog}
}

func (s *SQLiteBanStore) BanHardware(hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error {
	// check if already banned
	var existing []byte
	err := s.db.QueryRow("SELECT hardware_id FROM hardware_bans WHERE hardware_id = ?", hardwareID[:]).Scan(&existing)
	if err == nil {
		return ErrAlreadyBanned
	}
	if err != sql.ErrNoRows {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		"INSERT INTO hardware_bans (hardware_id, reason, banned_at, banned_by, note) VALUES (?, ?, ?, ?, ?)",
		hardwareID[:], string(reason), now, bannedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		s.auditLog.Log("ban", FormatHardwareID(hardwareID), string(reason), bannedBy, note)
	}

	return nil
}

func (s *SQLiteBanStore) IsBanned(hardwareID [32]byte) (*BanEntry, bool) {
	var entry BanEntry
	var hwid []byte
	var reason string
	err := s.db.QueryRow(
		"SELECT hardware_id, reason, banned_at, banned_by, note FROM hardware_bans WHERE hardware_id = ?",
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

func (s *SQLiteBanStore) UnbanHardware(hardwareID [32]byte) error {
	result, err := s.db.Exec("DELETE FROM hardware_bans WHERE hardware_id = ?", hardwareID[:])
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotBanned
	}

	if s.auditLog != nil {
		s.auditLog.Log("unban", FormatHardwareID(hardwareID), "", "", "")
	}

	return nil
}

func (s *SQLiteBanStore) ListBans() []BanEntry {
	return s.ListBansPage(0, 0)
}

func (s *SQLiteBanStore) ListBansPage(limit, offset int) []BanEntry {
	entries, err := s.ListBansPageE(limit, offset)
	if err != nil {
		return nil
	}
	return entries
}

func (s *SQLiteBanStore) ListBansPageE(limit, offset int) ([]BanEntry, error) {
	query := "SELECT hardware_id, reason, banned_at, banned_by, note FROM hardware_bans ORDER BY banned_at DESC"
	args := make([]any, 0, 2)
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
		if offset > 0 {
			query += " OFFSET ?"
			args = append(args, offset)
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

func (s *SQLiteBanStore) CountBans() int {
	total, err := s.CountBansE()
	if err != nil {
		return 0
	}
	return total
}

func (s *SQLiteBanStore) CountBansE() (int, error) {
	var total int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM hardware_bans").Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// implements AuditLog using the audit_log table
type SQLiteAuditLog struct {
	mu sync.Mutex
	db *sql.DB
}

// creates an audit log backed by the given database
func NewSQLiteAuditLog(db *sql.DB) *SQLiteAuditLog {
	return &SQLiteAuditLog{db: db}
}

func (l *SQLiteAuditLog) Log(action, targetID, reason, actor, note string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, err := l.db.Exec(
		"INSERT INTO audit_log (timestamp, action, target_id, reason, actor, note) VALUES (?, ?, ?, ?, ?, ?)",
		time.Now().UTC(), action, targetID, reason, actor, note,
	)
	return err
}

func (l *SQLiteAuditLog) Query(limit int) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	query := "SELECT id, timestamp, action, target_id, reason, actor, note FROM audit_log ORDER BY id DESC"
	if limit > 0 {
		query += " LIMIT ?"
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

// implements AttestationLog using the attestation_log table (migration v3)
type SQLiteAttestationLog struct {
	mu sync.Mutex
	db *sql.DB
}

// creates an attestation log backed by the given database
func NewSQLiteAttestationLog(db *sql.DB) *SQLiteAttestationLog {
	return &SQLiteAttestationLog{db: db}
}

func (l *SQLiteAttestationLog) Record(entry AttestationRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	_, err := l.db.Exec(
		`INSERT INTO attestation_log
		 (timestamp, client_id, hardware_id, result, duration_ms, pcr14, details, remote_addr)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, entry.ClientID, entry.HardwareID, entry.Result,
		entry.DurationMs, entry.PCR14, entry.Details, entry.RemoteAddr,
	)
	return err
}

func (l *SQLiteAttestationLog) QueryAttestations(limit int) []AttestationRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	query := `SELECT id, timestamp, client_id, hardware_id, result, duration_ms, pcr14, details, remote_addr
	          FROM attestation_log ORDER BY id DESC`
	if limit > 0 {
		query += " LIMIT ?"
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
