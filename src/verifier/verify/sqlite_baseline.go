// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Baseline Store
//
// Persistent PCR baseline storage backed by SQLite.
// Implements BaselineStorer for TOFU (Trust On First Use) validation
// with state surviving verifier restarts.

package verify

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// implements BaselineStorer using a SQLite database
// provides TOFU baseline persistence across verifier restarts
type SQLiteBaselineStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// creates a baseline store backed by the given database
func NewSQLiteBaselineStore(db *sql.DB) *SQLiteBaselineStore {
	return &SQLiteBaselineStore{db: db}
}

func (s *SQLiteBaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// check for existing baseline
	var storedPCR14, storedAgentHash []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, agent_hash, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR14, &storedAgentHash, &firstSeen, &lastSeen, &attestCount)

	if err == sql.ErrNoRows {
		// first use - establish baseline
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
		// query failed - refuse attestation to prevent re-TOFU with arbitrary PCR14
		return TOFUError, nil
	}

	// compare stored baseline
	var stored [types.HashSize]byte
	if len(storedPCR14) == types.HashSize {
		copy(stored[:], storedPCR14)
	}
	var agentHash [types.HashSize]byte
	if len(storedAgentHash) == types.HashSize {
		copy(agentHash[:], storedAgentHash)
	}

	if stored != pcr14 {
		// PCR mismatch detected - possible tampering, do not update baseline
		return TOFUMismatch, &ClientBaseline{
			PCR14:       stored,
			AgentHash:   agentHash,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			AttestCount: attestCount,
		}
	}

	// match
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

// CheckAndUpdateAgentHash pins agent_hash with TOFU semantics. The
// pcr14 column is filled on first use from currentPCR14 so the schema
// NOT NULL constraint is satisfied; the column carries no security
// meaning for boot-commitment clients - the verifier derives the
// expected PCR14 dynamically from agent_hash + ClockInfo.
func (s *SQLiteBaselineStore) CheckAndUpdateAgentHash(clientID string,
	currentPCR14, agentHash [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
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

	if !hasStored {
		// Legacy row from a pre-FlagBootCommitment attestation: the
		// PCR14 baseline is pinned but agent_hash is NULL. Record the
		// incoming hash so future rounds can verify it, but report the
		// transition as TOFULegacyBackfill so the caller can audit
		// (and, when configured, reject) the implicit trust upgrade.
		newCount := attestCount + 1
		if _, err := s.db.Exec(
			"UPDATE baselines SET agent_hash = ?, last_seen = ?, attest_count = ? WHERE client_id = ?",
			agentHash[:], now.UTC(), newCount, clientID,
		); err != nil {
			slog.Error("agent_hash backfill failed", "client_id", clientID, "error", err)
			return TOFUError, nil
		}
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

func (s *SQLiteBaselineStore) GetBaseline(clientID string) *ClientBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var storedPCR14 []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
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

// GetBootBaseline returns the persisted PCR0/PCR1/PCR7 row for a
// client or nil when the boot baseline has never been pinned. A row
// whose boot columns are still NULL counts as "not enrolled" and
// returns nil.
func (s *SQLiteBaselineStore) GetBootBaseline(clientID string) *BootBaseline {
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

func (s *SQLiteBaselineStore) ClearBaseline(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.db.Exec("DELETE FROM baselines WHERE client_id = ?", clientID)
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

func (s *SQLiteBaselineStore) Stats() BaselineStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := BaselineStats{}

	s.db.QueryRow("SELECT COUNT(*) FROM baselines").Scan(&stats.TotalClients)

	s.db.QueryRow("SELECT MIN(first_seen) FROM baselines").Scan(&stats.OldestBaseline)
	s.db.QueryRow("SELECT MAX(first_seen) FROM baselines").Scan(&stats.NewestBaseline)

	return stats
}

// CheckAndUpdateBootPCRs persists PCR0/PCR1/PCR7 alongside the existing
// PCR14 baseline. The boot columns are nullable so existing PCR14-only
// rows from older deployments TOFU-establish the firmware baseline on
// their next attestation rather than being rejected.
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
		// no row at all - cannot pin boot PCRs before the PCR14 baseline
		// was inserted. Surface as error so the caller fails closed.
		return TOFUError, nil
	}
	if err != nil {
		slog.Error("boot baseline SELECT failed",
			"client_id", clientID, "error", err)
		return TOFUError, nil
	}

	if len(storedPCR0) == 0 && len(storedPCR1) == 0 && len(storedPCR7) == 0 {
		// PCR14 row exists but no boot baseline yet - TOFU first use
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

// CheckAndUpdateAttestation commits the agent_hash pin and (when boot
// is non-nil) the firmware/SecureBoot pin in a single SQLite
// transaction held under BEGIN IMMEDIATE on a dedicated connection.
// BEGIN IMMEDIATE acquires SQLite's RESERVED write lock at the
// transaction start instead of upgrading from SHARED on the first
// write, so a second process attempting the same transaction blocks
// until the first COMMIT / ROLLBACK. Combined with PRAGMA
// busy_timeout=5000 from db.go this serialises every multi-process
// writer onto the baselines row and closes the window in which a
// CheckAndUpdateBootPCRs running in process B could observe a
// half-pinned row left behind by process A and TOFU-establish
// attacker-controlled PCR0/PCR1/PCR7.
//
// The function holds s.mu in addition to the SQL lock so the
// transaction is also single-writer inside the calling process; the
// database/sql connection pool is bypassed via db.Conn() so BEGIN
// IMMEDIATE, the SELECT/UPDATE statements, and COMMIT all run on the
// same underlying connection. A non-success branch ROLLBACKs and
// leaves the persistent row untouched, mirroring the existing split
// methods' semantics.
func (s *SQLiteBaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline) AttestationOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	outcome := AttestationOutcome{BootProvided: boot != nil}

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
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

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
		// fresh client: insert both halves in one statement.
		if boot != nil {
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

	// --- existing row: decide agent_hash branch ---
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
		// mismatch terminates the transaction without writes.
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

	// --- decide boot branch ---
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

	// --- commit phase: both halves passed; build a single UPDATE ---
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
