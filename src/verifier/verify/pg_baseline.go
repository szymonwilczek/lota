// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PostgreSQL Baseline Store
//
// Postgres counterpart of SQLiteBaselineStore.
// Same TOFU semantics; the cross-process serialization that SQLite gets
// from BEGIN IMMEDIATE is provided here by a per-client transaction-scoped
// advisory lock:
//
//	pg_advisory_xact_lock(hashtextextended(client_id, 0))
//
// Advisory lock serializes every writer for a given client_id even when
// no baseline row exists yet, which a bare SELECT ... FOR UPDATE cannot do
// (there is no row to lock on first use).
// Lock auto-releases on COMMIT/ROLLBACK.
//
// Advisory lock is the ONLY write fence, and it is deliberately per-client:
// independent clients commit concurrently, which is what lets registration
// bursts and steady-state attestation scale with the connection pool instead
// of serializing process-wide.
// Do not add a store-level mutex here -- *sql.DB is safe for concurrent use,
// every method is single statement or single transaction, and the SQLite store's
// process-wide write serialization is property of SQLite's single-writer model,
// not of the store contract.

package verify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// PostgresBaselineStore implements BaselineStorer, AgentHashStorer,
// BootBaselineStorer, BootBaselineReader and AtomicBaselineStorer
// against a shared Postgres database
type PostgresBaselineStore struct {
	db *sql.DB
}

// NewPostgresBaselineStore creates a baseline store backed by
// the given Postgres database
func NewPostgresBaselineStore(db *sql.DB) *PostgresBaselineStore {
	return &PostgresBaselineStore{db: db}
}

// lockClient takes the per-client transaction-scoped advisory lock so the
// SELECT/INSERT/UPDATE that follow run as one critical section against
// every other writer for the same client across all instances
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

// CheckAndUpdateAgentHash pins agent_hash with TOFU semantics.
// pcr14 column is filled on first use from currentPCR14 so the schema
// NOT NULL constraint is satisfied; it carries no security meaning for
// boot-commitment clients (the verifier derives the expected PCR14
// dynamically from agent_hash + ClockInfo)
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

	if !hasStored {
		newCount := attestCount + 1
		if _, err := tx.ExecContext(ctx,
			"UPDATE baselines SET agent_hash = $1, last_seen = $2, attest_count = $3 WHERE client_id = $4",
			agentHash[:], now.UTC(), newCount, clientID,
		); err != nil {
			slog.Error("agent_hash backfill failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		if err := tx.Commit(); err != nil {
			slog.Error("agent_hash backfill commit failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
		committed = true
		return TOFULegacyBackfill, &ClientBaseline{
			PCR14:       pcr14,
			AgentHash:   agentHash,
			FirstSeen:   firstSeen,
			LastSeen:    now,
			AttestCount: newCount,
		}
	}

	if stored != agentHash {
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

func (s *PostgresBaselineStore) GetBaseline(clientID string) *ClientBaseline {
	var storedPCR14 []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, first_seen, last_seen, attest_count FROM baselines WHERE client_id = $1",
		clientID,
	).Scan(&storedPCR14, &firstSeen, &lastSeen, &attestCount)
	if err != nil {
		return nil
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
	}
}

// GetBootBaseline returns the persisted PCR0/PCR1/PCR7 row for a client
// or nil when the boot baseline has never been pinned.
// A row whose boot columns are still NULL counts as "not enrolled"
// and returns nil.
func (s *PostgresBaselineStore) GetBootBaseline(clientID string) *BootBaseline {
	var (
		pcr0, pcr1, pcr7    []byte
		bootFirst, bootLast sql.NullTime
	)
	err := s.db.QueryRow(
		"SELECT pcr0, pcr1, pcr7, boot_first_seen, boot_last_seen FROM baselines WHERE client_id = $1",
		clientID,
	).Scan(&pcr0, &pcr1, &pcr7, &bootFirst, &bootLast)
	if err != nil {
		return nil
	}
	if len(pcr0) == 0 && len(pcr1) == 0 && len(pcr7) == 0 {
		return nil
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
	return &out
}

func (s *PostgresBaselineStore) ClearBaseline(clientID string) error {
	_, err := s.db.Exec("DELETE FROM baselines WHERE client_id = $1", clientID)
	return err
}

// SetClientTenant records the CA-assigned tenant on the baseline row
// Called per verified report, so the UPDATE is conditional:
// re-stamping tenant already in place matches no row and produces no WAL write,
// and the follow-up existence probe is a plain read.
// Only real tenant change pays for row rewrite.
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

// ClientTenant returns the recorded tenant.
// Client without baseline row or with pre-tenancy row is in the default tenant.
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

// CheckAndUpdateBootPCRs persists PCR0/PCR1/PCR7 alongside the existing
// PCR14 baseline.
// Boot columns are nullable so existing PCR14-only rows from older deployments
// TOFU-establish the firmware baseline on their next attestation rather than
// being rejected.
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
		// no row at all - cannot pin boot PCRs before the PCR14 baseline
		// was inserted.
		// Surface as error so the caller fails closed.
		return TOFUError, nil
	}
	if err != nil {
		slog.Error("boot baseline SELECT failed", "client_id", clientID, "error", err)
		return TOFUError, nil
	}

	if len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0 {
		// PCR14 row exists but no boot baseline yet - TOFU first use
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

// CheckAndUpdateAttestation commits the agent_hash pin and (when boot is
// non-nil) the firmware/SecureBoot pin in a single Postgres transaction.
// Per-client advisory lock taken at the top serializes the whole
// read-modify-write against every other writer for this client, the
// Postgres equivalent of the SQLite store's BEGIN IMMEDIATE contract: a
// second instance cannot observe a half-pinned row and TOFU-establish
// attacker-controlled PCR0/PCR1/PCR7.
// A non-success branch rolls back and leaves persistent state untouched.
func (s *PostgresBaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline,
) AttestationOutcome {
	ctx := context.Background()
	outcome := AttestationOutcome{BootProvided: boot != nil}

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
		// fresh client: insert both halves in one statement
		if boot != nil {
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

	// existing row: decide agent_hash branch
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
	case !hasStored:
		outcome.AgentHashResult = TOFULegacyBackfill
	case stored != agentHash:
		// mismatch terminates the transaction without writes
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

	// decide boot branch
	bootZero := len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0
	if boot != nil {
		if bootZero {
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

	// commit phase: both halves passed; build a single UPDATE
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

// GetReanchorState implements ReanchorStorer for Postgres.
// Present is true only when a boot baseline (PCR0/1/7) has been pinned for the client.
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

// ArchiveAndReanchor implements ReanchorStorer for Postgres:
// it archives the current boot baseline and replaces it with boot
// under the per-client advisory lock.
// esrt_capable is kept sticky (OR), never cleared.
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
	// FOR UPDATE locks the row, and last_reanchor_at is read under that lock,
	// so the rate-limit guard below cannot be raced by a concurrent re-anchor
	// running on another verifier instance
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
	// LFA re-anchor applies automatically but flags the client for post-fact
	// operator review;
	// strong re-anchor clears any prior flag
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

// RecordBootEvidence stores the event log + ESRT version for a first-use
// boot baseline (Postgres).
// Idempotent UPDATE; esrt_capable kept sticky.
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

// ListLFAReviewPending returns clients with an unreviewed LFA re-anchor
// (Postgres).
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

// AcknowledgeLFAReview clears a client's pending-review flag (Postgres).
func (s *PostgresBaselineStore) AcknowledgeLFAReview(clientID string) error {
	_, err := s.db.ExecContext(context.Background(),
		"UPDATE baselines SET lfa_review_pending = FALSE WHERE client_id = $1", clientID)
	return err
}
