// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL revocation, ban, audit and attestation logs

package store

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"
)

// PostgresRevocationStore implements RevocationStore on the revocations
// table.
type PostgresRevocationStore struct {
	mu       sync.RWMutex
	db       *sql.DB
	auditLog AuditLog
}

// NewPostgresRevocationStore returns a revocation store on db that logs
// each action to auditLog when it is non-nil.
func NewPostgresRevocationStore(db *sql.DB, auditLog AuditLog) *PostgresRevocationStore {
	return &PostgresRevocationStore{db: db, auditLog: auditLog}
}

func (s *PostgresRevocationStore) Revoke(tenant, clientID string, reason RevocationReason, revokedBy, note string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = rollbackOnErr(tx, err)
		}
	}()

	res, err := tx.Exec(
		"INSERT INTO revocations (client_id, tenant, reason, "+
			"revoked_at, revoked_by, note) "+
			"VALUES ($1, $2, $3, $4, $5, $6) "+
			"ON CONFLICT (client_id) DO NOTHING",
		clientID, tenant, string(reason), time.Now().UTC(), revokedBy,
		note,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrAlreadyRevoked
	}

	return commitAudited(tx, s.auditLog, tenant, "revoke", clientID,
		string(reason), revokedBy, note)
}

func (s *PostgresRevocationStore) IsRevoked(clientID string,
) (*RevocationEntry, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var entry RevocationEntry
	var reason string
	err := s.db.QueryRow(
		"SELECT client_id, tenant, reason, revoked_at, revoked_by, note FROM revocations WHERE client_id = $1",
		clientID,
	).Scan(&entry.ClientID, &entry.Tenant, &reason, &entry.RevokedAt, &entry.RevokedBy, &entry.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	entry.Reason = RevocationReason(reason)
	return &entry, true, nil
}

func (s *PostgresRevocationStore) Unrevoke(clientID, reason, actor, note string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = rollbackOnErr(tx, err)
		}
	}()

	// deleted row carries the tenant the audit entry records
	var tenant string
	err = tx.QueryRow("DELETE FROM revocations WHERE client_id = $1 "+
		"RETURNING tenant", clientID).Scan(&tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotRevoked
	}
	if err != nil {
		return err
	}

	return commitAudited(tx, s.auditLog, tenant, "unrevoke", clientID,
		reason, actor, note)
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

// PostgresBanStore implements BanStore on the hardware_bans table.
type PostgresBanStore struct {
	db       *sql.DB
	auditLog AuditLog
}

// NewPostgresBanStore returns a ban store on db that logs each action to
// auditLog when it is non-nil.
func NewPostgresBanStore(db *sql.DB, auditLog AuditLog) *PostgresBanStore {
	return &PostgresBanStore{db: db, auditLog: auditLog}
}

func (s *PostgresBanStore) BanHardware(tenant string, hardwareID [32]byte, reason RevocationReason, bannedBy, note string) (err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = rollbackOnErr(tx, err)
		}
	}()

	res, err := tx.Exec(
		"INSERT INTO hardware_bans (tenant, hardware_id, reason, "+
			"banned_at, banned_by, note) "+
			"VALUES ($1, $2, $3, $4, $5, $6) "+
			"ON CONFLICT (tenant, hardware_id) DO NOTHING",
		tenant, hardwareID[:], string(reason), time.Now().UTC(),
		bannedBy, note,
	)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrAlreadyBanned
	}

	return commitAudited(tx, s.auditLog, tenant, "ban",
		FormatHardwareID(hardwareID), string(reason), bannedBy, note)
}

func (s *PostgresBanStore) IsBanned(tenant string, hardwareID [32]byte,
) (*BanEntry, bool, error) {
	var entry BanEntry
	var hwid []byte
	var reason string
	err := s.db.QueryRow(
		"SELECT tenant, hardware_id, reason, banned_at, banned_by, note FROM hardware_bans WHERE tenant = $1 AND hardware_id = $2",
		tenant, hardwareID[:],
	).Scan(&entry.Tenant, &hwid, &reason, &entry.BannedAt, &entry.BannedBy, &entry.Note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	if len(hwid) == 32 {
		copy(entry.HardwareID[:], hwid)
	}
	entry.Reason = RevocationReason(reason)
	return &entry, true, nil
}

func (s *PostgresBanStore) UnbanHardware(tenant string, hardwareID [32]byte, reason, actor, note string) (err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = rollbackOnErr(tx, err)
		}
	}()

	result, err := tx.Exec("DELETE FROM hardware_bans "+
		"WHERE tenant = $1 AND hardware_id = $2", tenant, hardwareID[:])
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

	return commitAudited(tx, s.auditLog, tenant, "unban",
		FormatHardwareID(hardwareID), reason, actor, note)
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

// PostgresAuditLog implements AuditLog on the audit_log table.
type PostgresAuditLog struct {
	db *sql.DB
}

// NewPostgresAuditLog returns an audit log on db.
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

func (l *PostgresAuditLog) logTx(tx *sql.Tx,
	tenant, action, targetID, reason, actor, note string,
) error {
	_, err := tx.Exec(
		"INSERT INTO audit_log (timestamp, tenant, action, "+
			"target_id, reason, actor, note) "+
			"VALUES ($1, $2, $3, $4, $5, $6, $7)",
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

// PostgresAttestationLog implements AttestationLog on the attestation_log
// table.
type PostgresAttestationLog struct {
	db     *sql.DB
	window time.Duration // zero records every round
}

// NewPostgresAttestationLog returns an attestation log on db that collapses
// rounds within window.
func NewPostgresAttestationLog(db *sql.DB, window time.Duration) *PostgresAttestationLog {
	return &PostgresAttestationLog{db: db, window: window}
}

const pgStandingQuery = `SELECT ` + attestationStandingCols + `
	 FROM attestation_log WHERE tenant = $1 AND client_id = $2
	 ORDER BY id DESC LIMIT 1`

// pgSubjectLock is held until commit and also covers a subject with no row.
const pgSubjectLock = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// pgSubjectKey joins tenant and client ID with 0x1f; NUL is not valid
// Postgres text.
func pgSubjectKey(r *AttestationRecord) string {
	return r.Tenant + "\x1f" + r.ClientID
}

// pgLockSubjects locks each subject once, in sorted order, so two batches
// cannot deadlock.
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

// record extends the standing row or inserts a new one.
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

// Record records entry in its own transaction under the subject lock.
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

// RecordBatch records entries in one transaction; each round sees the ones
// before it.
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

// QueryAttestations returns matching rows, newest first. A zero query
// returns the whole log.
func (l *PostgresAttestationLog) QueryAttestations(q AttestationQuery) []AttestationRecord {
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
