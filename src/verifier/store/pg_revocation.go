// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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
	"slices"
	"strconv"
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

func (s *PostgresRevocationStore) Revoke(tenant, clientID string, reason RevocationReason, revokedBy, note string) error {
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
		"INSERT INTO revocations (client_id, tenant, reason, revoked_at, revoked_by, note) VALUES ($1, $2, $3, $4, $5, $6)",
		clientID, tenant, string(reason), now, revokedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log(tenant, "revoke", clientID, string(reason), revokedBy, note); err != nil {
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
		"SELECT client_id, tenant, reason, revoked_at, revoked_by, note FROM revocations WHERE client_id = $1",
		clientID,
	).Scan(&entry.ClientID, &entry.Tenant, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note)
	if err != nil {
		return nil, false
	}

	entry.Reason = RevocationReason(reason)
	return &entry, true
}

func (s *PostgresRevocationStore) Unrevoke(clientID, reason, actor, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// deleted row carries the tenant the audit entry records
	var tenant string
	err := s.db.QueryRow("DELETE FROM revocations WHERE client_id = $1 RETURNING tenant", clientID).Scan(&tenant)
	if err == sql.ErrNoRows {
		return ErrNotRevoked
	}
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log(tenant, "unrevoke", clientID, reason, actor, note); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresRevocationStore) ListRevocations() []RevocationEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT client_id, tenant, reason, revoked_at, revoked_by, note FROM revocations ORDER BY revoked_at DESC",
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []RevocationEntry
	for rows.Next() {
		var entry RevocationEntry
		var reason string
		if err := rows.Scan(&entry.ClientID, &entry.Tenant, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note); err == nil {
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

func (s *PostgresBanStore) BanHardware(tenant string, hardwareID [32]byte, reason RevocationReason, bannedBy, note string) error {
	var existing []byte
	err := s.db.QueryRow("SELECT hardware_id FROM hardware_bans WHERE tenant = $1 AND hardware_id = $2",
		tenant, hardwareID[:]).Scan(&existing)
	if err == nil {
		return ErrAlreadyBanned
	}
	if err != sql.ErrNoRows {
		return err
	}

	now := time.Now().UTC()
	_, err = s.db.Exec(
		"INSERT INTO hardware_bans (tenant, hardware_id, reason, banned_at, banned_by, note) VALUES ($1, $2, $3, $4, $5, $6)",
		tenant, hardwareID[:], string(reason), now, bannedBy, note,
	)
	if err != nil {
		return err
	}

	if s.auditLog != nil {
		if err := s.auditLog.Log(tenant, "ban", FormatHardwareID(hardwareID), string(reason), bannedBy, note); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresBanStore) IsBanned(tenant string, hardwareID [32]byte) (*BanEntry, bool) {
	var entry BanEntry
	var hwid []byte
	var reason string
	err := s.db.QueryRow(
		"SELECT tenant, hardware_id, reason, banned_at, banned_by, note FROM hardware_bans WHERE tenant = $1 AND hardware_id = $2",
		tenant, hardwareID[:],
	).Scan(&entry.Tenant, &hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note)
	if err != nil {
		return nil, false
	}

	if len(hwid) == 32 {
		copy(entry.HardwareID[:], hwid)
	}
	entry.Reason = RevocationReason(reason)
	return &entry, true
}

func (s *PostgresBanStore) UnbanHardware(tenant string, hardwareID [32]byte, reason, actor, note string) error {
	result, err := s.db.Exec("DELETE FROM hardware_bans WHERE tenant = $1 AND hardware_id = $2",
		tenant, hardwareID[:])
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
		if err := s.auditLog.Log(tenant, "unban", FormatHardwareID(hardwareID), reason, actor, note); err != nil {
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
	query := "SELECT tenant, hardware_id, reason, banned_at, banned_by, note FROM hardware_bans ORDER BY banned_at DESC"
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
		if err := rows.Scan(&entry.Tenant, &hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note); err == nil {
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

	query := "SELECT tenant, hardware_id, reason, banned_at, banned_by, note FROM hardware_bans"
	args := make([]any, 0, 7)

	if nextID != "" {
		cursor, err := DecodeBanCursor(nextID)
		if err != nil {
			return nil, err
		}
		query += ` WHERE (banned_at < $1)
			OR (banned_at = $2 AND hardware_id < $3)
			OR (banned_at = $4 AND hardware_id = $5 AND tenant < $6)
			ORDER BY banned_at DESC, hardware_id DESC, tenant DESC LIMIT $7`
		args = append(args, cursor.BannedAt,
			cursor.BannedAt, cursor.HardwareID[:],
			cursor.BannedAt, cursor.HardwareID[:], cursor.Tenant, limit)
	} else {
		query += " ORDER BY banned_at DESC, hardware_id DESC, tenant DESC LIMIT $1"
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
		if err := rows.Scan(&entry.Tenant, &hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note); err == nil {
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
// No store-level lock:
// every method is a single statement against the concurrency-safe *sql.DB,
// and Log runs on operator actions and revocation events -- process-wide mutex
// here only serializes callers for no correctness gain
type PostgresAuditLog struct {
	db *sql.DB
}

// NewPostgresAuditLog creates an audit log backed by the given
// Postgres database
func NewPostgresAuditLog(db *sql.DB) *PostgresAuditLog {
	return &PostgresAuditLog{db: db}
}

func (l *PostgresAuditLog) Log(tenant, action, targetID, reason, actor, note string) error {
	_, err := l.db.Exec(
		"INSERT INTO audit_log (timestamp, tenant, action, target_id, reason, actor, note) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		time.Now().UTC(), tenant, action, targetID, reason, actor, note,
	)
	return err
}

func (l *PostgresAuditLog) Query(limit int) []AuditEntry {
	query := "SELECT id, timestamp, tenant, action, target_id, reason, actor, note FROM audit_log ORDER BY id DESC"
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
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.Tenant, &entry.Action, &entry.TargetID, &entry.Reason, &entry.Actor, &entry.Note); err == nil {
			entries = append(entries, entry)
		}
	}
	return entries
}

// PostgresAttestationLog implements AttestationLog using
// the attestation_log table
// No store-level lock:
// Record is one transaction on the attestation hot path (one call per verified report),
// so process-wide mutex here caps fleet attestation throughput at one commit latency per report
type PostgresAttestationLog struct {
	db     *sql.DB
	window time.Duration // zero records every round
}

// NewPostgresAttestationLog creates an attestation log backed by
// the given Postgres database
func NewPostgresAttestationLog(db *sql.DB) *PostgresAttestationLog {
	return NewPostgresAttestationLogWindow(db, DefaultCollapseWindow)
}

// the same, with a deployment's own collapse window
func NewPostgresAttestationLogWindow(db *sql.DB, window time.Duration) *PostgresAttestationLog {
	return &PostgresAttestationLog{db: db, window: window}
}

const pgStandingQuery = `SELECT ` + attestationStandingCols + `
	 FROM attestation_log WHERE tenant = $1 AND client_id = $2
	 ORDER BY id DESC LIMIT 1`

// held to commit; also covers a host with no row yet
const pgSubjectLock = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// client IDs are unique per tenant; NUL is not valid Postgres text
func pgSubjectKey(r *AttestationRecord) string {
	return r.Tenant + "\x1f" + r.ClientID
}

// lock each subject once, in one order, so two batches cannot deadlock
func pgLockSubjects(x attestationExecer, entries []AttestationRecord) error {
	keys := make([]string, 0, len(entries))
	for i := range entries {
		keys = append(keys, pgSubjectKey(&entries[i]))
	}
	slices.Sort(keys)
	for _, k := range slices.Compact(keys) {
		if _, err := x.Exec(pgSubjectLock, k); err != nil {
			return err
		}
	}
	return nil
}

const pgExtendStanding = `UPDATE attestation_log
	 SET last_seen = $1, rounds = rounds + 1, duration_ms = $2, remote_addr = $3
	 WHERE id = $4`

const pgInsertRow = `INSERT INTO attestation_log
	 (timestamp, tenant, client_id, hardware_id, result, duration_ms, pcr14,
	  details, remote_addr, kernel_hash, last_seen, rounds)
	 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1)`

// extend the standing row or open a new one
func (l *PostgresAttestationLog) record(x attestationExecer, entry AttestationRecord, now time.Time) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = now
	}

	// reentrant: free when RecordBatch already holds it
	if _, err := x.Exec(pgSubjectLock, pgSubjectKey(&entry)); err != nil {
		return err
	}

	id, standing := attestationStanding(x, pgStandingQuery, entry.Tenant, entry.ClientID)
	if id != 0 && attestationCollapses(standing, entry, l.window) {
		_, err := x.Exec(pgExtendStanding, entry.Timestamp, entry.DurationMs,
			entry.RemoteAddr, id)
		return err
	}

	_, err := x.Exec(pgInsertRow, entry.Timestamp, entry.Tenant, entry.ClientID,
		entry.HardwareID, entry.Result, entry.DurationMs, entry.PCR14,
		entry.Details, entry.RemoteAddr, entry.KernelHash, entry.Timestamp)
	return err
}

// read and extend the standing row under the subject lock
func (l *PostgresAttestationLog) Record(entry AttestationRecord) error {
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	if err := l.record(tx, entry, time.Now().UTC()); err != nil {
		return rollbackOnErr(tx, err)
	}
	return tx.Commit()
}

// each round sees the ones before it, as if recorded one by one
func (l *PostgresAttestationLog) RecordBatch(entries []AttestationRecord) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := l.db.Begin()
	if err != nil {
		return err
	}

	if err := pgLockSubjects(tx, entries); err != nil {
		return rollbackOnErr(tx, err)
	}

	now := time.Now().UTC()
	for i := range entries {
		if err := l.record(tx, entries[i], now); err != nil {
			return rollbackOnErr(tx, err)
		}
	}
	return tx.Commit()
}

const pgAttestationSelect = `SELECT id, timestamp, tenant, client_id, hardware_id,
	 result, duration_ms, pcr14, details, remote_addr, kernel_hash, last_seen, rounds
	 FROM attestation_log`

func (l *PostgresAttestationLog) QueryAttestations(limit int) []AttestationRecord {
	return l.QueryAttestationsFiltered(AttestationQuery{Limit: limit})
}

// zero query: the whole log, newest first
func (l *PostgresAttestationLog) QueryAttestationsFiltered(q AttestationQuery) []AttestationRecord {
	// timestamptz compares instants; the bound goes as UTC
	where, args := attestationQueryClauses(q, func(n int) string {
		return "$" + strconv.Itoa(n)
	}, func(t time.Time) any { return t.UTC() })
	// #nosec G202 -- constant fragments and placeholders; values are arguments
	query := pgAttestationSelect + where + " ORDER BY id DESC"
	if q.Limit > 0 {
		query += " LIMIT $" + strconv.Itoa(len(args)+1)
		args = append(args, q.Limit)
	}

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var entries []AttestationRecord
	for rows.Next() {
		var e AttestationRecord
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Tenant, &e.ClientID, &e.HardwareID,
			&e.Result, &e.DurationMs, &e.PCR14, &e.Details, &e.RemoteAddr,
			&e.KernelHash, &e.LastSeen, &e.Rounds); err == nil {
			entries = append(entries, e)
		}
	}
	return entries
}
