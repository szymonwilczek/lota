// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL baseline store
//
// The check-and-pin, re-anchor and agent-hash re-pin transactions of one
// client serialize on a transaction-scoped advisory lock, which holds before
// the client has a row:
//
//	pg_advisory_xact_lock(hashtextextended(client_id, 0))
//
// Different clients commit concurrently.

package verify

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// PostgresBaselineStore is the baseline store on a Postgres database the
// verifier instances share.
type PostgresBaselineStore struct {
	db *sql.DB
}

// NewPostgresBaselineStore returns a baseline store on db.
func NewPostgresBaselineStore(db *sql.DB) *PostgresBaselineStore {
	return &PostgresBaselineStore{db: db}
}

// lockClient takes the client's advisory lock for the rest of tx.
func lockClient(ctx context.Context, tx *sql.Tx, clientID string) error {
	_, err := tx.ExecContext(ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", clientID)
	return err
}

func (s *PostgresBaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	ctx := context.Background()
	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("baseline tx begin failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("baseline tx rollback failed", "client_id", clientID, "error", err)
			}
		}
	}()

	if err := lockClient(ctx, tx, clientID); err != nil {
		slog.Error("baseline advisory lock failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}

	var storedPCR14, storedAgentHash []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err = tx.QueryRowContext(ctx,
		"SELECT pcr14, agent_hash, first_seen, last_seen, attest_count FROM baselines WHERE client_id = $1 FOR UPDATE",
		clientID,
	).Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen, &attestCount)

	if err == sql.ErrNoRows {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO baselines (client_id, pcr14, first_seen, last_seen, attest_count) VALUES ($1, $2, $3, $4, 1)",
			clientID, pcr14[:], now.UTC(), now.UTC(),
		); err != nil {
			slog.Error("baseline INSERT failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		if err := tx.Commit(); err != nil {
			slog.Error("baseline INSERT commit failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		committed = true
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
	if _, err = tx.ExecContext(ctx,
		"UPDATE baselines SET last_seen = $1, attest_count = $2 WHERE client_id = $3",
		now.UTC(), newCount, clientID,
	); err != nil {
		slog.Warn("baseline update failed", "client_id", clientID, "error", err)
	}
	if err := tx.Commit(); err != nil {
		slog.Error("baseline update commit failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed = true

	return TOFUMatch, &ClientBaseline{
		PCR14:       stored,
		AgentHash:   agentHash,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		AttestCount: newCount,
	}
}

// CheckAndUpdateAgentHash implements AgentHashStorer.
func (s *PostgresBaselineStore) CheckAndUpdateAgentHash(clientID string,
	currentPCR14, agentHash [types.HashSize]byte,
) (TOFUResult, *ClientBaseline) {
	ctx := context.Background()
	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("agent_hash tx begin failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("baseline tx rollback failed", "client_id", clientID, "error", err)
			}
		}
	}()

	if err := lockClient(ctx, tx, clientID); err != nil {
		slog.Error("agent_hash advisory lock failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}

	var storedPCR14, storedAgentHash []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err = tx.QueryRowContext(ctx,
		"SELECT pcr14, agent_hash, first_seen, last_seen, attest_count FROM baselines WHERE client_id = $1 FOR UPDATE",
		clientID,
	).Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen, &attestCount)

	if err == sql.ErrNoRows {
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO baselines (client_id, pcr14, agent_hash, first_seen, last_seen, attest_count) VALUES ($1, $2, $3, $4, $5, 1)",
			clientID, currentPCR14[:], agentHash[:], now.UTC(), now.UTC(),
		); err != nil {
			slog.Error("agent_hash baseline INSERT failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		if err := tx.Commit(); err != nil {
			slog.Error("agent_hash INSERT commit failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		committed = true
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
	if _, err := tx.ExecContext(ctx,
		"UPDATE baselines SET last_seen = $1, attest_count = $2 WHERE client_id = $3",
		now.UTC(), newCount, clientID,
	); err != nil {
		slog.Warn("agent_hash baseline update failed", "client_id", clientID, "error", err)
	}
	if err := tx.Commit(); err != nil {
		slog.Error("agent_hash update commit failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed = true
	return TOFUMatch, &ClientBaseline{
		PCR14:       pcr14,
		AgentHash:   stored,
		FirstSeen:   firstSeen,
		LastSeen:    now,
		AttestCount: newCount,
	}
}

func (s *PostgresBaselineStore) GetBaseline(clientID string,
) (*ClientBaseline, error) {
	var storedPCR14 []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, first_seen, last_seen, attest_count FROM baselines WHERE client_id = $1",
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

// GetBootBaseline implements BootBaselineReader. A row with NULL boot
// columns has no boot baseline.
func (s *PostgresBaselineStore) GetBootBaseline(clientID string,
) (*BootBaseline, error) {
	var (
		pcr0, pcr1, pcr7    []byte
		bootFirst, bootLast sql.NullTime
	)
	err := s.db.QueryRow(
		"SELECT pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen FROM baselines WHERE client_id = $1",
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

func (s *PostgresBaselineStore) ClearBaseline(clientID string) error {
	_, err := s.db.Exec("DELETE FROM baselines WHERE client_id = $1", clientID)
	return err
}

// SetClientTenant implements TenantStorer. A row that already holds this
// tenant is not rewritten.
func (s *PostgresBaselineStore) SetClientTenant(clientID, tenant string) error {
	res, err := s.db.Exec(
		"UPDATE baselines SET tenant = $1 WHERE client_id = $2 AND tenant <> $1",
		tenant, clientID)
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
			"SELECT 1 FROM baselines WHERE client_id = $1", clientID).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("no baseline row for client %q", clientID)
		}
		return err
	}
	return nil
}

// ClientTenant implements TenantStorer.
func (s *PostgresBaselineStore) ClientTenant(clientID string) (string, error) {
	var tenant string
	err := s.db.QueryRow(
		"SELECT tenant FROM baselines WHERE client_id = $1", clientID).Scan(&tenant)
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

func (s *PostgresBaselineStore) ListClients() []string {
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

func (s *PostgresBaselineStore) ListClientsAfter(tenants []string,
	after string, limit int,
) ([]string, error) {
	q, args := clientsAfterQuery(tenants, after, limit,
		func(n int) string { return "$" + strconv.Itoa(n) })
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	return scanClientIDs(rows)
}

func (s *PostgresBaselineStore) Stats() BaselineStats {
	stats := BaselineStats{}

	if err := s.db.QueryRow("SELECT COUNT(*) FROM baselines").Scan(&stats.TotalClients); err != nil {
		return stats
	}

	var oldest, newest sql.NullTime
	if err := s.db.QueryRow("SELECT MIN(first_seen) FROM baselines").Scan(&oldest); err != nil {
		return stats
	}
	if err := s.db.QueryRow("SELECT MAX(first_seen) FROM baselines").Scan(&newest); err != nil {
		return stats
	}
	if oldest.Valid {
		stats.OldestBaseline = oldest.Time
	}
	if newest.Valid {
		stats.NewestBaseline = newest.Time
	}

	return stats
}

// CheckAndUpdateBootPCRs implements BootBaselineStorer on an existing row:
// a client with no row is TOFUError.
func (s *PostgresBaselineStore) CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline) {
	ctx := context.Background()
	now := time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("boot baseline tx begin failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("baseline tx rollback failed", "client_id", clientID, "error", err)
			}
		}
	}()

	if err := lockClient(ctx, tx, clientID); err != nil {
		slog.Error("boot baseline advisory lock failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}

	var (
		storedPCR0, storedPCR1, storedPCR7 []byte
		bootFirst, bootLast                sql.NullTime
	)

	err = tx.QueryRowContext(ctx,
		"SELECT pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen FROM baselines WHERE client_id = $1 FOR UPDATE",
		clientID,
	).Scan(&storedPCR0, &storedPCR1, &storedPCR7, &bootFirst, &bootLast)

	if err == sql.ErrNoRows {
		return TOFUError, nil
	}
	if err != nil {
		slog.Error("boot baseline SELECT failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}

	if len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0 {
		if _, err := tx.ExecContext(ctx,
			"UPDATE baselines SET pcr0 = $1, pcr1 = $2, pcr7 = $3, boot_first_seen = $4, boot_last_seen = $5 WHERE client_id = $6",
			boot.PCR0[:], boot.PCR1[:], boot.PCR7[:], now.UTC(), now.UTC(), clientID,
		); err != nil {
			slog.Error("boot baseline INSERT failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		if err := tx.Commit(); err != nil {
			slog.Error("boot baseline first-use commit failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		committed = true

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

	if _, err = tx.ExecContext(ctx,
		"UPDATE baselines SET boot_last_seen = $1 WHERE client_id = $2",
		now.UTC(), clientID,
	); err != nil {
		slog.Warn("boot baseline update failed", "client_id", clientID, "error", err)
	}
	if err := tx.Commit(); err != nil {
		slog.Error("boot baseline match commit failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}
	committed = true

	stored.LastSeen = now
	return TOFUMatch, &stored
}

// CheckAndUpdateAttestation implements AtomicBaselineStorer in one
// transaction under lockClient. A branch that does not commit rolls back.
func (s *PostgresBaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline, consent bool,
) AttestationOutcome {
	ctx := context.Background()
	outcome := AttestationOutcome{BootProvided: boot != nil, PCR14Result: TOFUError}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("attestation tx: begin failed", "client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("attestation tx: rollback failed", "client_id", clientID, "error", err)
			}
		}
	}()

	spent := func() bool {
		res, err := tx.ExecContext(ctx,
			"DELETE FROM forced_reanchors WHERE client_id = $1", clientID)
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

	if err := lockClient(ctx, tx, clientID); err != nil {
		slog.Error("attestation tx: advisory lock failed", "client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}

	var (
		storedPCR14, storedAgentHash       []byte
		storedPCR0, storedPCR1, storedPCR7 []byte
		firstSeen, lastSeen                time.Time
		attestCount                        uint64
		bootFirst, bootLast                sql.NullTime
	)
	err = tx.QueryRowContext(ctx, `
		SELECT pcr14, agent_hash, first_seen, last_seen, attest_count,
		       pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen
		  FROM baselines WHERE client_id = $1 FOR UPDATE`, clientID).
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
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO baselines (
					client_id, pcr14, agent_hash, first_seen, last_seen,
					attest_count, pcr0, pcr1, pcr7, boot_first_seen,
					boot_last_seen
				) VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8, $9, $10)`,
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
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO baselines (
					client_id, pcr14, agent_hash, first_seen, last_seen,
					attest_count
				) VALUES ($1, $2, $3, $4, $5, 1)`,
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
		if err := tx.Commit(); err != nil {
			slog.Error("attestation tx: COMMIT failed", "client_id", clientID, "error", err)
			outcome.AgentHashResult = TOFUError
			if boot != nil {
				outcome.BootResult = TOFUError
			}
			return outcome
		}
		committed = true
		return outcome

	case err != nil:
		slog.Error("attestation tx: SELECT failed", "client_id", clientID, "error", err)
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
			if _, err := tx.ExecContext(ctx, `
				UPDATE baselines
				   SET agent_hash      = $1,
				       last_seen       = $2,
				       attest_count    = $3,
				       pcr0            = $4,
				       pcr1            = $5,
				       pcr7            = $6,
				       boot_first_seen = $7,
				       boot_last_seen  = $8
				 WHERE client_id = $9`,
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
			if _, err := tx.ExecContext(ctx, `
				UPDATE baselines
				   SET agent_hash     = $1,
				       last_seen      = $2,
				       attest_count   = $3,
				       boot_last_seen = $4
				 WHERE client_id = $5`,
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
		if _, err := tx.ExecContext(ctx, `
			UPDATE baselines
			   SET agent_hash   = $1,
			       last_seen    = $2,
			       attest_count = $3
			 WHERE client_id = $4`,
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

	if err := tx.Commit(); err != nil {
		slog.Error("attestation tx: COMMIT failed", "client_id", clientID, "error", err)
		outcome.AgentHashResult = TOFUError
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	committed = true
	return outcome
}

// GetReanchorState implements ReanchorStorer. Present is false when the
// client has no boot baseline.
func (s *PostgresBaselineStore) GetReanchorState(clientID string) ReanchorState {
	ctx := context.Background()
	var (
		pcr0, pcr1, pcr7 []byte
		evlog            []byte
		esrtVersion      sql.NullInt64
		esrtCapable      sql.NullBool
		lfa              sql.NullBool
		reCount          sql.NullInt64
		lastReanchor     sql.NullTime
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT pcr0, pcr1, pcr7, eventlog_baseline, esrt_version,
		   esrt_capable, lfa, reanchor_count, last_reanchor_at
		 FROM baselines WHERE client_id = $1`,
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
		// #nosec G115 -- uint32 ESRT version stored in a signed BIGINT column, round-tripped back to its source type
		st.ESRTVersion = uint32(esrtVersion.Int64)
	}
	st.ESRTCapable = esrtCapable.Valid && esrtCapable.Bool
	st.LFA = lfa.Valid && lfa.Bool
	if reCount.Valid {
		st.ReanchorCount = int(reCount.Int64)
	}
	if lastReanchor.Valid {
		st.LastReanchorAt = lastReanchor.Time
	}
	return st
}

// ArchiveAndReanchor implements ReanchorStorer.
func (s *PostgresBaselineStore) ArchiveAndReanchor(clientID string,
	boot BootBaseline, eventLog []byte, esrtVersion uint32,
	esrtCapable, lfa bool, reason string, now time.Time,
) error {
	ctx := context.Background()
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("reanchor tx rollback failed", "client_id", clientID, "error", err)
			}
		}
	}()
	if err := lockClient(ctx, tx, clientID); err != nil {
		return err
	}

	var (
		oldPCR0, oldPCR1, oldPCR7 []byte
		oldESRT                   sql.NullInt64
		lastReanchor              sql.NullTime
	)
	if err := tx.QueryRowContext(ctx,
		"SELECT pcr0, pcr1, pcr7, esrt_version, last_reanchor_at FROM baselines WHERE client_id = $1 FOR UPDATE",
		clientID,
	).Scan(&oldPCR0, &oldPCR1, &oldPCR7, &oldESRT, &lastReanchor); err != nil {
		return err
	}
	if lastReanchor.Valid &&
		now.Sub(lastReanchor.Time.UTC()) < reanchorInterval(lfa) {
		return ErrReanchorRateLimited
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO baseline_archive
		   (client_id, archived_at, pcr0, pcr1, pcr7, esrt_version, reason)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		clientID, now, oldPCR0, oldPCR1, oldPCR7, oldESRT, reason,
	); err != nil {
		return err
	}
	// a strong re-anchor clears a pending LFA review
	if _, err := tx.ExecContext(ctx,
		`UPDATE baselines SET pcr0 = $1, pcr1 = $2, pcr7 = $3, boot_last_seen = $4,
		   eventlog_baseline = $5, esrt_version = $6,
		   esrt_capable = (esrt_capable OR $7),
		   lfa = $8, lfa_review_pending = $8,
		   reanchor_count = reanchor_count + 1, last_reanchor_at = $9
		 WHERE client_id = $10`,
		boot.PCR0[:], boot.PCR1[:], boot.PCR7[:], now,
		eventLog, int64(esrtVersion), esrtCapable, lfa, now, clientID,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// GetAgentHashRepinState implements AgentHashRepinStorer.
func (s *PostgresBaselineStore) GetAgentHashRepinState(clientID string) AgentHashRepinState {
	ctx := context.Background()

	var (
		count     sql.NullInt64
		lastRepin sql.NullTime
		agentHash []byte
	)
	if err := s.db.QueryRowContext(ctx,
		`SELECT agent_hash, agent_hash_repin_count, last_agent_hash_repin_at
		   FROM baselines WHERE client_id = $1`,
		clientID,
	).Scan(&agentHash, &count, &lastRepin); err != nil {
		// a store error reads as a missing row: no re-pin
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("agent-hash re-pin state read failed",
				"client_id", clientID, "error", err)
		}
		return AgentHashRepinState{}
	}
	st := AgentHashRepinState{
		Present:    true,
		Pinned:     len(agentHash) == types.HashSize,
		RepinCount: int(count.Int64),
	}
	if lastRepin.Valid {
		st.LastRepinAt = lastRepin.Time.UTC()
	}
	return st
}

// ArchiveAndRepinAgentHash implements AgentHashRepinStorer.
func (s *PostgresBaselineStore) ArchiveAndRepinAgentHash(clientID string,
	agentHash, pcr14 [types.HashSize]byte, now time.Time,
) error {
	ctx := context.Background()
	now = now.UTC()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if err := tx.Rollback(); err != nil {
				slog.Warn("agent-hash re-pin tx rollback failed",
					"client_id", clientID, "error", err)
			}
		}
	}()
	if err := lockClient(ctx, tx, clientID); err != nil {
		return err
	}

	var (
		oldAgentHash []byte
		lastRepin    sql.NullTime
	)
	if err := tx.QueryRowContext(ctx,
		`SELECT agent_hash, last_agent_hash_repin_at
		   FROM baselines WHERE client_id = $1 FOR UPDATE`,
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
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO baseline_archive
		   (client_id, archived_at, agent_hash, reason)
		 VALUES ($1, $2, $3, $4)`,
		clientID, now, oldAgentHash, "agent-update",
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE baselines SET agent_hash = $1, pcr14 = $2, last_seen = $3,
		   agent_hash_repin_count = agent_hash_repin_count + 1,
		   last_agent_hash_repin_at = $4
		 WHERE client_id = $5`,
		agentHash[:], pcr14[:], now, now, clientID,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// RepinPCR14 moves the pinned PCR 14 and the boot evidence. The WHERE on
// the old register is the race guard.
func (s *PostgresBaselineStore) RepinPCR14(clientID string,
	from, to [types.HashSize]byte, eventLog []byte, now time.Time,
) error {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE baselines SET pcr14 = $1, eventlog_baseline = $2, last_seen = $3
		 WHERE client_id = $4 AND pcr14 = $5`,
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

// RecordBootEvidence implements ReanchorStorer.
func (s *PostgresBaselineStore) RecordBootEvidence(clientID string,
	eventLog []byte, esrtVersion uint32, esrtPresent bool,
) error {
	ctx := context.Background()
	_, err := s.db.ExecContext(ctx,
		`UPDATE baselines SET eventlog_baseline = $1, esrt_version = $2,
		   esrt_capable = (esrt_capable OR $3)
		 WHERE client_id = $4`,
		eventLog, int64(esrtVersion), esrtPresent, clientID,
	)
	return err
}

// ListLFAReviewPending implements ReanchorStorer.
func (s *PostgresBaselineStore) ListLFAReviewPending() []string {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT client_id FROM baselines WHERE lfa_review_pending = TRUE ORDER BY client_id")
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
func (s *PostgresBaselineStore) AcknowledgeLFAReview(clientID string) error {
	res, err := s.db.ExecContext(context.Background(),
		"UPDATE baselines SET lfa_review_pending = FALSE WHERE client_id = $1 AND lfa_review_pending",
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
func (s *PostgresBaselineStore) MarkForcedReanchor(clientID string) error {
	_, err := s.db.ExecContext(context.Background(),
		"INSERT INTO forced_reanchors (client_id) VALUES ($1) "+
			"ON CONFLICT (client_id) DO NOTHING",
		clientID)
	return err
}

// HasForcedReanchor implements ForcedReanchorStorer.
func (s *PostgresBaselineStore) HasForcedReanchor(clientID string,
) (bool, error) {
	var one int
	err := s.db.QueryRowContext(context.Background(),
		"SELECT 1 FROM forced_reanchors WHERE client_id = $1", clientID).
		Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// TakeForcedReanchor implements ForcedReanchorStorer.
func (s *PostgresBaselineStore) TakeForcedReanchor(clientID string,
) (bool, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM forced_reanchors WHERE client_id = $1", clientID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RecordKernelHash implements KernelHashRecorder.
// An unchanged hash writes nothing.
func (s *PostgresBaselineStore) RecordKernelHash(clientID string,
	kernelHash [types.HashSize]byte,
) (prev [types.HashSize]byte, had bool, err error) {
	var stored []byte
	if err := s.db.QueryRow(
		`SELECT kernel_hash FROM baselines WHERE client_id = $1`,
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
		`UPDATE baselines SET kernel_hash = $1 WHERE client_id = $2`,
		kernelHash[:], clientID,
	); err != nil {
		return prev, had, err
	}

	return prev, had, nil
}

// RecordMachineKeys implements MachineKeysRecorder. An unchanged list writes
// nothing, so a round costs a read.
func (s *PostgresBaselineStore) RecordMachineKeys(clientID string, keys []byte) ([]byte, error) {
	var stored sql.NullString
	if err := s.db.QueryRow(
		`SELECT machine_keys FROM baselines WHERE client_id = $1`,
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
		`UPDATE baselines SET machine_keys = $1 WHERE client_id = $2`,
		string(keys), clientID,
	); err != nil {
		return prev, err
	}
	return prev, nil
}

// GetMachineKeys implements MachineKeysRecorder.
func (s *PostgresBaselineStore) GetMachineKeys(clientID string) []byte {
	var stored sql.NullString
	if err := s.db.QueryRow(
		`SELECT machine_keys FROM baselines WHERE client_id = $1`,
		clientID,
	).Scan(&stored); err != nil || !stored.Valid {
		return nil
	}
	return []byte(stored.String)
}
