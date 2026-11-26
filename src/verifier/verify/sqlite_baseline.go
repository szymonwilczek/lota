// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - SQLite baseline store

package verify

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// SQLiteBaselineStore is the baseline store on a SQLite database.
// s.mu makes it single-writer inside the process.
type SQLiteBaselineStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewSQLiteBaselineStore returns a baseline store on db.
func NewSQLiteBaselineStore(db *sql.DB) *SQLiteBaselineStore {
	return &SQLiteBaselineStore{db: db}
}

func (s *SQLiteBaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	var storedPCR14, storedAgentHash []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, agent_hash, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen, &attestCount)

	if err == sql.ErrNoRows {
		_, err := s.db.Exec(
			"INSERT INTO baselines (client_id, pcr14, first_seen, last_seen, attest_count) VALUES (?, ?, ?, ?, 1)",
			clientID, pcr14[:], now.UTC(), now.UTC(),
		)
		if err != nil {
			slog.Error("baseline INSERT failed",
				"client_id", clientID, "error", err)
			return TOFUError, nil
		}

		return TOFUFirstUse, &ClientBaseline{
			PCR14:       pcr14,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
	}

	if err != nil {
		return TOFUError, nil
	}

	var stored [types.HashSize]byte
	if len(storedPCR14) == types.HashSize {
		copy(stored[:], storedPCR14)
	}
	var agentHash [types.HashSize]byte
	if len(storedAgentHash) == types.HashSize {
		copy(agentHash[:], storedAgentHash)
	}

	if stored != pcr14 {
		return TOFUMismatch, &ClientBaseline{
			PCR14:       stored,
			AgentHash:   agentHash,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			AttestCount: attestCount,
		}
	}

	newCount := attestCount + 1
	_, err = s.db.Exec(
		"UPDATE baselines SET last_seen = ?, attest_count = ? WHERE client_id = ?",
		now.UTC(), newCount, clientID,
	)
	if err != nil {
		slog.Warn("baseline update failed", "client_id", clientID, "error", err)
	}

	return TOFUMatch, &ClientBaseline{
		PCR14:       stored,
		AgentHash:   agentHash,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		AttestCount: newCount,
	}
}

// CheckAndUpdateAgentHash implements AgentHashStorer.
func (s *SQLiteBaselineStore) CheckAndUpdateAgentHash(clientID string,
	currentPCR14, agentHash [types.HashSize]byte,
) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	var storedPCR14, storedAgentHash []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, agent_hash, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen, &attestCount)

	if err == sql.ErrNoRows {
		_, err := s.db.Exec(
			"INSERT INTO baselines (client_id, pcr14, agent_hash, first_seen, last_seen, attest_count) VALUES (?, ?, ?, ?, ?, 1)",
			clientID, currentPCR14[:], agentHash[:], now.UTC(), now.UTC(),
		)
		if err != nil {
			slog.Error("agent_hash baseline INSERT failed",
				"client_id", clientID, "error", err)
			return TOFUError, nil
		}
		return TOFUFirstUse, &ClientBaseline{
			PCR14:       currentPCR14,
			AgentHash:   agentHash,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
	}
	if err != nil {
		return TOFUError, nil
	}

	var pcr14 [types.HashSize]byte
	if len(storedPCR14) == types.HashSize {
		copy(pcr14[:], storedPCR14)
	}
	var stored [types.HashSize]byte
	hasStored := len(storedAgentHash) == types.HashSize
	if hasStored {
		copy(stored[:], storedAgentHash)
	}

	// a NULL agent_hash is an out-of-band PCR14 pin and mismatches
	if !hasStored || stored != agentHash {
		return TOFUMismatch, &ClientBaseline{
			PCR14:       pcr14,
			AgentHash:   stored,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			AttestCount: attestCount,
		}
	}

	newCount := attestCount + 1
	if _, err := s.db.Exec(
		"UPDATE baselines SET last_seen = ?, attest_count = ? WHERE client_id = ?",
		now.UTC(), newCount, clientID,
	); err != nil {
		slog.Warn("agent_hash baseline update failed", "client_id", clientID, "error", err)
	}
	return TOFUMatch, &ClientBaseline{
		PCR14:       pcr14,
		AgentHash:   stored,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		AttestCount: newCount,
	}
}

func (s *SQLiteBaselineStore) GetBaseline(clientID string,
) (*ClientBaseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var storedPCR14 []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR14, &firstSeen, &lastSeen, &attestCount)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var pcr14 [types.HashSize]byte
	if len(storedPCR14) == types.HashSize {
		copy(pcr14[:], storedPCR14)
	}

	return &ClientBaseline{
		PCR14:       pcr14,
		FirstSeen:   firstSeen,
		LastSeen:    lastSeen,
		AttestCount: attestCount,
	}, nil
}

// GetBootBaseline implements BootBaselineReader.
// A row with NULL boot columns has no boot baseline.
func (s *SQLiteBaselineStore) GetBootBaseline(clientID string,
) (*BootBaseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		pcr0, pcr1, pcr7    []byte
		bootFirst, bootLast sql.NullTime
	)
	err := s.db.QueryRow(
		"SELECT pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&pcr0, &pcr1, &pcr7, &bootFirst, &bootLast)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(pcr0) == 0 && len(pcr1) == 0 && len(pcr7) == 0 {
		return nil, nil
	}

	out := BootBaseline{}
	if len(pcr0) == types.HashSize {
		copy(out.PCR0[:], pcr0)
	}
	if len(pcr1) == types.HashSize {
		copy(out.PCR1[:], pcr1)
	}
	if len(pcr7) == types.HashSize {
		copy(out.PCR7[:], pcr7)
	}
	if bootFirst.Valid {
		out.FirstSeen = bootFirst.Time
	}
	if bootLast.Valid {
		out.LastSeen = bootLast.Time
	}
	return &out, nil
}

func (s *SQLiteBaselineStore) ClearBaseline(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM baselines WHERE client_id = ?", clientID)
	return err
}

// SetClientTenant implements TenantStorer.
// A row that already holds this tenant is not rewritten.
func (s *SQLiteBaselineStore) SetClientTenant(clientID, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(
		"UPDATE baselines SET tenant = ? WHERE client_id = ? AND tenant <> ?",
		tenant, clientID, tenant)
	if err != nil {
		return fmt.Errorf("tenant UPDATE failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var one int
		err := s.db.QueryRow(
			"SELECT 1 FROM baselines WHERE client_id = ?", clientID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no baseline row for client %q", clientID)
		}
		return err
	}
	return nil
}

// ClientTenant implements TenantStorer.
func (s *SQLiteBaselineStore) ClientTenant(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var tenant string
	err := s.db.QueryRow(
		"SELECT tenant FROM baselines WHERE client_id = ?", clientID).Scan(&tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultTenant, nil
	}
	if err != nil {
		return "", fmt.Errorf("tenant SELECT failed: %w", err)
	}
	if tenant == "" {
		return DefaultTenant, nil
	}
	return tenant, nil
}

func (s *SQLiteBaselineStore) ListClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT client_id FROM baselines ORDER BY client_id")
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

func (s *SQLiteBaselineStore) ListClientsAfter(tenants []string,
	after string, limit int,
) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q, args := clientsAfterQuery(tenants, after, limit,
		func(int) string { return "?" })
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanClientIDs(rows)
}

func (s *SQLiteBaselineStore) CountClients(tenants []string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q, args := countClientsQuery(tenants, func(int) string { return "?" })
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLiteBaselineStore) Stats() BaselineStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := BaselineStats{}

	if err := s.db.QueryRow("SELECT COUNT(*) FROM baselines").Scan(&stats.TotalClients); err != nil {
		return stats
	}

	if err := s.db.QueryRow("SELECT MIN(first_seen) FROM baselines").Scan(&stats.OldestBaseline); err != nil {
		return stats
	}
	if err := s.db.QueryRow("SELECT MAX(first_seen) FROM baselines").Scan(&stats.NewestBaseline); err != nil {
		return stats
	}

	return stats
}

// CheckAndUpdateBootPCRs implements BootBaselineStorer on an existing row:
// a client with no row is TOFUError.
func (s *SQLiteBaselineStore) CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	var (
		storedPCR0, storedPCR1, storedPCR7 []byte
		bootFirst, bootLast                sql.NullTime
	)

	err := s.db.QueryRow(
		"SELECT pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR0, &storedPCR1, &storedPCR7, &bootFirst, &bootLast)

	if err == sql.ErrNoRows {
		return TOFUError, nil
	}
	if err != nil {
		slog.Error("boot baseline SELECT failed",
			"client_id", clientID, "error", err)
		return TOFUError, nil
	}

	if len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0 {
		_, err := s.db.Exec(
			"UPDATE baselines SET pcr0 = ?, pcr1 = ?, pcr7 = ?, boot_first_seen = ?, boot_last_seen = ? WHERE client_id = ?",
			boot.PCR0[:], boot.PCR1[:], boot.PCR7[:], now.UTC(), now.UTC(), clientID,
		)
		if err != nil {
			slog.Error("boot baseline INSERT failed",
				"client_id", clientID, "error", err)
			return TOFUError, nil
		}

		out := boot
		out.FirstSeen = now
		out.LastSeen = now
		return TOFUFirstUse, &out
	}

	var stored BootBaseline
	if len(storedPCR0) == types.HashSize {
		copy(stored.PCR0[:], storedPCR0)
	}
	if len(storedPCR1) == types.HashSize {
		copy(stored.PCR1[:], storedPCR1)
	}
	if len(storedPCR7) == types.HashSize {
		copy(stored.PCR7[:], storedPCR7)
	}
	if bootFirst.Valid {
		stored.FirstSeen = bootFirst.Time
	}
	if bootLast.Valid {
		stored.LastSeen = bootLast.Time
	}

	if stored.PCR0 != boot.PCR0 || stored.PCR1 != boot.PCR1 || stored.PCR7 != boot.PCR7 {
		return TOFUMismatch, &stored
	}

	_, err = s.db.Exec(
		"UPDATE baselines SET boot_last_seen = ? WHERE client_id = ?",
		now.UTC(), clientID,
	)
	if err != nil {
		slog.Warn("boot baseline update failed", "client_id", clientID, "error", err)
	}

	stored.LastSeen = now
	return TOFUMatch, &stored
}

// CheckAndUpdateAttestation implements AtomicBaselineStorer. BEGIN IMMEDIATE
// takes the write lock at the start of the transaction, so another process
// blocks until COMMIT or ROLLBACK, up to busy_timeout. The transaction runs
// on one db.Conn() because BEGIN, the statements and COMMIT must share a
// connection. A branch that does not commit rolls back.
func (s *SQLiteBaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline, consent bool,
) AttestationOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	outcome := AttestationOutcome{BootProvided: boot != nil, PCR14Result: TOFUError}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		slog.Error("attestation tx: acquire conn failed",
			"client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		slog.Error("attestation tx: BEGIN IMMEDIATE failed",
			"client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	committed := false
	defer func() {
		if !committed {
			if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
				slog.Warn("attestation tx: rollback failed",
					"client_id", clientID, "error", err)
			}
		}
	}()

	spent := func() bool {
		res, err := conn.ExecContext(ctx,
			"DELETE FROM forced_reanchors WHERE client_id = ?", clientID)
		var n int64
		if err == nil {
			n, err = res.RowsAffected()
		}
		if err != nil || n == 0 {
			slog.Error("attestation tx: forced re-anchor consent not spent",
				"client_id", clientID, "error", err)
			outcome.AgentHashResult = TOFUError
			outcome.PCR14Result = TOFUError
			outcome.BootResult = TOFUError
			return false
		}
		return true
	}

	var (
		storedPCR14, storedAgentHash       []byte
		storedPCR0, storedPCR1, storedPCR7 []byte
		firstSeen, lastSeen                time.Time
		attestCount                        uint64
		bootFirst, bootLast                sql.NullTime
	)
	err = conn.QueryRowContext(ctx, `
		SELECT pcr14, agent_hash, first_seen, last_seen, attest_count,
		       pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen
		  FROM baselines WHERE client_id = ?`, clientID).
		Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen,
			&attestCount, &storedPCR0, &storedPCR1, &storedPCR7,
			&bootFirst, &bootLast)

	now := time.Now()
	switch {
	case err == sql.ErrNoRows:
		if boot != nil {
			if consent && !spent() {
				return outcome
			}
			if _, err := conn.ExecContext(ctx, `
				INSERT INTO baselines (
					client_id, pcr14, agent_hash, first_seen, last_seen,
					attest_count, pcr0, pcr1, pcr7, boot_first_seen,
					boot_last_seen
				) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
				clientID, pcr14[:], agentHash[:], now.UTC(), now.UTC(),
				boot.PCR0[:], boot.PCR1[:], boot.PCR7[:],
				now.UTC(), now.UTC()); err != nil {
				slog.Error("attestation tx: INSERT (with boot) failed",
					"client_id", clientID, "error", err)
				outcome.AgentHashResult = TOFUError
				outcome.BootResult = TOFUError
				return outcome
			}
			outcome.AgentHashResult = TOFUFirstUse
			outcome.AgentHashBaseline = &ClientBaseline{
				PCR14: pcr14, AgentHash: agentHash,
				FirstSeen: now, LastSeen: now, AttestCount: 1,
			}
			outcome.PCR14Result = TOFUFirstUse
			outcome.BootResult = TOFUFirstUse
			bb := *boot
			bb.FirstSeen, bb.LastSeen = now, now
			outcome.BootBaseline = &bb
		} else {
			if _, err := conn.ExecContext(ctx, `
				INSERT INTO baselines (
					client_id, pcr14, agent_hash, first_seen, last_seen,
					attest_count
				) VALUES (?, ?, ?, ?, ?, 1)`,
				clientID, pcr14[:], agentHash[:], now.UTC(), now.UTC()); err != nil {
				slog.Error("attestation tx: INSERT (agent_hash only) failed",
					"client_id", clientID, "error", err)
				outcome.AgentHashResult = TOFUError
				return outcome
			}
			outcome.AgentHashResult = TOFUFirstUse
			outcome.AgentHashBaseline = &ClientBaseline{
				PCR14: pcr14, AgentHash: agentHash,
				FirstSeen: now, LastSeen: now, AttestCount: 1,
			}
			outcome.PCR14Result = TOFUFirstUse
		}
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			slog.Error("attestation tx: COMMIT failed",
				"client_id", clientID, "error", err)
			outcome.AgentHashResult = TOFUError
			if boot != nil {
				outcome.BootResult = TOFUError
			}
			return outcome
		}
		committed = true
		return outcome

	case err != nil:
		slog.Error("attestation tx: SELECT failed",
			"client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}

	var stored [types.HashSize]byte
	hasStored := len(storedAgentHash) == types.HashSize
	if hasStored {
		copy(stored[:], storedAgentHash)
	}
	var pcr14Stored [types.HashSize]byte
	if len(storedPCR14) == types.HashSize {
		copy(pcr14Stored[:], storedPCR14)
	}

	switch {
	case !hasStored || stored != agentHash:
		outcome.AgentHashResult = TOFUMismatch
		outcome.AgentHashBaseline = &ClientBaseline{
			PCR14: pcr14Stored, AgentHash: stored,
			FirstSeen: firstSeen, LastSeen: lastSeen,
			AttestCount: attestCount,
		}
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	default:
		outcome.AgentHashResult = TOFUMatch
	}

	// pcr14 is NOT NULL: every row has one to compare
	switch {
	case pcr14Stored != pcr14:
		outcome.PCR14Result = TOFUMismatch
		outcome.AgentHashBaseline = &ClientBaseline{
			PCR14: pcr14Stored, AgentHash: stored,
			FirstSeen: firstSeen, LastSeen: lastSeen,
			AttestCount: attestCount,
		}
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	default:
		outcome.PCR14Result = TOFUMatch
	}

	bootZero := len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0
	if boot != nil {
		if bootZero {
			if consent && !spent() {
				return outcome
			}
			outcome.BootResult = TOFUFirstUse
		} else {
			var storedBoot BootBaseline
			if len(storedPCR0) == types.HashSize {
				copy(storedBoot.PCR0[:], storedPCR0)
			}
			if len(storedPCR1) == types.HashSize {
				copy(storedBoot.PCR1[:], storedPCR1)
			}
			if len(storedPCR7) == types.HashSize {
				copy(storedBoot.PCR7[:], storedPCR7)
			}
			if bootFirst.Valid {
				storedBoot.FirstSeen = bootFirst.Time
			}
			if bootLast.Valid {
				storedBoot.LastSeen = bootLast.Time
			}
			if storedBoot.PCR0 != boot.PCR0 ||
				storedBoot.PCR1 != boot.PCR1 ||
				storedBoot.PCR7 != boot.PCR7 {
				outcome.AgentHashBaseline = &ClientBaseline{
					PCR14: pcr14Stored, AgentHash: stored,
					FirstSeen: firstSeen, LastSeen: lastSeen,
					AttestCount: attestCount,
				}
				outcome.BootResult = TOFUMismatch
				outcome.BootBaseline = &storedBoot
				return outcome
			}
			outcome.BootResult = TOFUMatch
		}
	}

	newCount := attestCount + 1
	if boot != nil {
		switch outcome.BootResult {
		case TOFUFirstUse:
			if _, err := conn.ExecContext(ctx, `
				UPDATE baselines
				   SET agent_hash      = ?,
				       last_seen       = ?,
				       attest_count    = ?,
				       pcr0            = ?,
				       pcr1            = ?,
				       pcr7            = ?,
				       boot_first_seen = ?,
				       boot_last_seen  = ?
				 WHERE client_id = ?`,
				agentHash[:], now.UTC(), newCount,
				boot.PCR0[:], boot.PCR1[:], boot.PCR7[:],
				now.UTC(), now.UTC(), clientID); err != nil {
				slog.Error("attestation tx: UPDATE (boot first-use) failed",
					"client_id", clientID, "error", err)
				outcome.AgentHashResult = TOFUError
				outcome.BootResult = TOFUError
				return outcome
			}
			bb := *boot
			bb.FirstSeen, bb.LastSeen = now, now
			outcome.BootBaseline = &bb
		case TOFUMatch:
			if _, err := conn.ExecContext(ctx, `
				UPDATE baselines
				   SET agent_hash     = ?,
				       last_seen      = ?,
				       attest_count   = ?,
				       boot_last_seen = ?
				 WHERE client_id = ?`,
				agentHash[:], now.UTC(), newCount, now.UTC(), clientID); err != nil {
				slog.Error("attestation tx: UPDATE (boot match) failed",
					"client_id", clientID, "error", err)
				outcome.AgentHashResult = TOFUError
				outcome.BootResult = TOFUError
				return outcome
			}
			outcome.BootBaseline = &BootBaseline{
				PCR0: boot.PCR0, PCR1: boot.PCR1, PCR7: boot.PCR7,
				FirstSeen: bootFirst.Time, LastSeen: now,
			}
		}
	} else {
		if _, err := conn.ExecContext(ctx, `
			UPDATE baselines
			   SET agent_hash   = ?,
			       last_seen    = ?,
			       attest_count = ?
			 WHERE client_id = ?`,
			agentHash[:], now.UTC(), newCount, clientID); err != nil {
			slog.Error("attestation tx: UPDATE (agent_hash only) failed",
				"client_id", clientID, "error", err)
			outcome.AgentHashResult = TOFUError
			return outcome
		}
	}

	outcome.AgentHashBaseline = &ClientBaseline{
		PCR14:       pcr14Stored,
		AgentHash:   agentHash,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		AttestCount: newCount,
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		slog.Error("attestation tx: COMMIT failed",
			"client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	committed = true
	return outcome
}

// GetReanchorState implements ReanchorStorer.
// Present is false when the client has no boot baseline.
func (s *SQLiteBaselineStore) GetReanchorState(clientID string) ReanchorState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		pcr0, pcr1, pcr7 []byte
		evlog            []byte
		esrtVersion      sql.NullInt64
		esrtCapable      sql.NullInt64
		lfa              sql.NullInt64
		reCount          sql.NullInt64
		lastReanchor     sql.NullTime
	)
	err := s.db.QueryRow(
		`SELECT pcr0, pcr1, pcr7, eventlog_baseline, esrt_version,
		   esrt_capable, lfa, reanchor_count, last_reanchor_at
		 FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&pcr0, &pcr1, &pcr7, &evlog, &esrtVersion, &esrtCapable,
		&lfa, &reCount, &lastReanchor)
	if err != nil {
		return ReanchorState{}
	}
	if len(pcr0) == 0 && len(pcr1) == 0 && len(pcr7) == 0 {
		return ReanchorState{}
	}

	st := ReanchorState{Present: true}
	if len(evlog) > 0 {
		st.EventLogBaseline = append([]byte(nil), evlog...)
	}
	if esrtVersion.Valid {
		// #nosec G115 -- uint32 ESRT version stored in a signed INTEGER column, round-tripped back to its source type
		st.ESRTVersion = uint32(esrtVersion.Int64)
	}
	st.ESRTCapable = esrtCapable.Valid && esrtCapable.Int64 != 0
	st.LFA = lfa.Valid && lfa.Int64 != 0
	if reCount.Valid {
		st.ReanchorCount = int(reCount.Int64)
	}
	if lastReanchor.Valid {
		st.LastReanchorAt = lastReanchor.Time
	}
	return st
}

// ArchiveAndReanchor implements ReanchorStorer.
func (s *SQLiteBaselineStore) ArchiveAndReanchor(clientID string,
	boot BootBaseline, eventLog []byte, esrtVersion uint32,
	esrtCapable, lfa bool, reason string, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		// runs after a successful Commit too
		// ErrTxDone is benign there
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Warn("reanchor tx rollback failed", "client_id", clientID, "error", err)
		}
	}()

	var (
		oldPCR0, oldPCR1, oldPCR7 []byte
		oldESRT                   sql.NullInt64
		lastReanchor              sql.NullTime
	)
	if err := tx.QueryRow(
		"SELECT pcr0, pcr1, pcr7, esrt_version, last_reanchor_at FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&oldPCR0, &oldPCR1, &oldPCR7, &oldESRT, &lastReanchor); err != nil {
		return err
	}
	if lastReanchor.Valid &&
		now.Sub(lastReanchor.Time.UTC()) < reanchorInterval(lfa) {
		return ErrReanchorRateLimited
	}
	if _, err = tx.Exec(
		`INSERT INTO baseline_archive
		   (client_id, archived_at, pcr0, pcr1, pcr7, esrt_version, reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		clientID, now, oldPCR0, oldPCR1, oldPCR7, oldESRT, reason,
	); err != nil {
		return err
	}

	capVal, lfaVal := 0, 0
	if esrtCapable {
		capVal = 1
	}
	if lfa {
		lfaVal = 1
	}
	// a strong re-anchor clears a pending LFA review
	if _, err = tx.Exec(
		`UPDATE baselines SET pcr0 = ?, pcr1 = ?, pcr7 = ?, boot_last_seen = ?,
		   eventlog_baseline = ?, esrt_version = ?,
		   esrt_capable = MAX(COALESCE(esrt_capable, 0), ?),
		   lfa = ?, lfa_review_pending = ?,
		   reanchor_count = COALESCE(reanchor_count, 0) + 1,
		   last_reanchor_at = ?
		 WHERE client_id = ?`,
		boot.PCR0[:], boot.PCR1[:], boot.PCR7[:], now,
		eventLog, esrtVersion, capVal, lfaVal, lfaVal, now, clientID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// GetAgentHashRepinState implements AgentHashRepinStorer.
func (s *SQLiteBaselineStore) GetAgentHashRepinState(clientID string) AgentHashRepinState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var (
		count     sql.NullInt64
		lastPin   sql.NullTime
		state     AgentHashRepinState
		clientPK  string
		agentHash []byte
	)
	if err := s.db.QueryRow(
		`SELECT client_id, agent_hash, agent_hash_repin_count,
		        last_agent_hash_repin_at
		   FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&clientPK, &agentHash, &count, &lastPin); err != nil {
		// a store error reads as a missing row: no re-pin
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("agent-hash re-pin state read failed",
				"client_id", clientID, "error", err)
		}
		return AgentHashRepinState{}
	}
	state.Present = true
	state.Pinned = len(agentHash) == types.HashSize
	state.RepinCount = int(count.Int64)
	if lastPin.Valid {
		state.LastRepinAt = lastPin.Time.UTC()
	}
	return state
}

// ArchiveAndRepinAgentHash implements AgentHashRepinStorer.
func (s *SQLiteBaselineStore) ArchiveAndRepinAgentHash(clientID string,
	agentHash, pcr14 [types.HashSize]byte, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Warn("agent-hash re-pin tx rollback failed",
				"client_id", clientID, "error", err)
		}
	}()

	var (
		oldAgentHash []byte
		lastRepin    sql.NullTime
	)

	if err := tx.QueryRow(
		`SELECT agent_hash, last_agent_hash_repin_at
		   FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&oldAgentHash, &lastRepin); err != nil {
		return err
	}
	if len(oldAgentHash) != types.HashSize {
		return ErrAgentHashNotPinned
	}
	if lastRepin.Valid &&
		now.Sub(lastRepin.Time.UTC()) < AgentHashRepinMinInterval {
		return ErrAgentHashRepinRateLimited
	}
	if _, err = tx.Exec(
		`INSERT INTO baseline_archive
		   (client_id, archived_at, agent_hash, reason)
		 VALUES (?, ?, ?, ?)`,
		clientID, now, oldAgentHash, "agent-update",
	); err != nil {
		return err
	}
	if _, err = tx.Exec(
		`UPDATE baselines SET agent_hash = ?, pcr14 = ?, last_seen = ?,
		   agent_hash_repin_count = COALESCE(agent_hash_repin_count, 0) + 1,
		   last_agent_hash_repin_at = ?
		 WHERE client_id = ?`,
		agentHash[:], pcr14[:], now, now, clientID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// RepinPCR14 moves the pinned PCR 14 and the boot evidence.
// The WHERE on the old register is the race guard.
func (s *SQLiteBaselineStore) RepinPCR14(clientID string,
	from, to [types.HashSize]byte, eventLog []byte, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(
		`UPDATE baselines SET pcr14 = ?, eventlog_baseline = ?, last_seen = ?
		 WHERE client_id = ? AND pcr14 = ?`,
		to[:], eventLog, now.UTC(), clientID, from[:],
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrPCR14RepinRaced
	}
	return nil
}

// RepinBootEntries moves the pinned PCR 1 and the boot evidence.
// The WHERE on the old boot registers is the race guard.
func (s *SQLiteBaselineStore) RepinBootEntries(clientID string,
	from BootBaseline, pcr1 [types.HashSize]byte, eventLog []byte,
	now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(
		`UPDATE baselines SET pcr1 = ?, eventlog_baseline = ?,
		   boot_last_seen = ?
		 WHERE client_id = ? AND pcr0 = ? AND pcr1 = ? AND pcr7 = ?`,
		pcr1[:], eventLog, now.UTC(), clientID,
		from.PCR0[:], from.PCR1[:], from.PCR7[:],
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrBootEntryRepinRaced
	}
	return nil
}

// RecordBootEvidence implements ReanchorStorer.
func (s *SQLiteBaselineStore) RecordBootEvidence(clientID string,
	eventLog []byte, esrtVersion uint32, esrtPresent bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	capVal := 0
	if esrtPresent {
		capVal = 1
	}
	_, err := s.db.Exec(
		`UPDATE baselines SET eventlog_baseline = ?, esrt_version = ?,
		   esrt_capable = MAX(COALESCE(esrt_capable, 0), ?)
		 WHERE client_id = ?`,
		eventLog, esrtVersion, capVal, clientID,
	)
	return err
}

// ListLFAReviewPending implements ReanchorStorer.
func (s *SQLiteBaselineStore) ListLFAReviewPending() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		"SELECT client_id FROM baselines WHERE lfa_review_pending = 1 ORDER BY client_id")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

// AcknowledgeLFAReview implements ReanchorStorer.
func (s *SQLiteBaselineStore) AcknowledgeLFAReview(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		"UPDATE baselines SET lfa_review_pending = 0 WHERE client_id = ? AND lfa_review_pending = 1",
		clientID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoReviewPending
	}
	return nil
}

// MarkForcedReanchor implements ForcedReanchorStorer.
func (s *SQLiteBaselineStore) MarkForcedReanchor(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		"INSERT OR IGNORE INTO forced_reanchors (client_id) VALUES (?)",
		clientID)
	return err
}

// HasForcedReanchor implements ForcedReanchorStorer.
func (s *SQLiteBaselineStore) HasForcedReanchor(clientID string,
) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var one int
	err := s.db.QueryRow(
		"SELECT 1 FROM forced_reanchors WHERE client_id = ?", clientID).
		Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// TakeForcedReanchor implements ForcedReanchorStorer.
func (s *SQLiteBaselineStore) TakeForcedReanchor(clientID string,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(
		"DELETE FROM forced_reanchors WHERE client_id = ?", clientID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RecordKernelHash implements KernelHashRecorder.
// An unchanged hash writes nothing.
func (s *SQLiteBaselineStore) RecordKernelHash(clientID string,
	kernelHash [types.HashSize]byte,
) (prev [types.HashSize]byte, had bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var stored []byte
	if err := s.db.QueryRow(
		`SELECT kernel_hash FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return prev, false, nil
		}
		return prev, false, err
	}

	if len(stored) == types.HashSize {
		copy(prev[:], stored)
		had = true
	}

	if had && prev == kernelHash {
		return prev, had, nil
	}

	if _, err := s.db.Exec(
		`UPDATE baselines SET kernel_hash = ? WHERE client_id = ?`,
		kernelHash[:], clientID,
	); err != nil {
		return prev, had, err
	}

	return prev, had, nil
}

// RecordMachineKeys implements MachineKeysRecorder. An unchanged list writes
// nothing, so a round costs a read.
func (s *SQLiteBaselineStore) RecordMachineKeys(clientID string, keys []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var stored sql.NullString
	if err := s.db.QueryRow(
		`SELECT machine_keys FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&stored); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	var prev []byte
	if stored.Valid {
		prev = []byte(stored.String)
	}
	if bytes.Equal(prev, keys) {
		return prev, nil
	}

	if _, err := s.db.Exec(
		`UPDATE baselines SET machine_keys = ? WHERE client_id = ?`,
		string(keys), clientID,
	); err != nil {
		return prev, err
	}
	return prev, nil
}

// GetMachineKeys implements MachineKeysRecorder.
func (s *SQLiteBaselineStore) GetMachineKeys(clientID string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stored sql.NullString
	if err := s.db.QueryRow(
		`SELECT machine_keys FROM baselines WHERE client_id = ?`,
		clientID,
	).Scan(&stored); err != nil || !stored.Valid {
		return nil
	}
	return []byte(stored.String)
}
