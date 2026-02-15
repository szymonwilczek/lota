// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite Baseline Store
//
// Persistent PCR baseline storage backed by SQLite.
// Implements BaselineStorer for TOFU (Trust On First Use) validation
// with state surviving verifier restarts.

package verify

import (
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
	var storedPCR14 []byte
	var firstSeen, lastSeen time.Time
	var attestCount uint64

	err := s.db.QueryRow(
		"SELECT pcr14, first_seen, last_seen, attest_count FROM baselines WHERE client_id = ?",
		clientID,
	).Scan(&storedPCR14, &firstSeen, &lastSeen, &attestCount)

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

	if stored != pcr14 {
		// PCR mismatch detected - possible tampering, do not update baseline
		return TOFUMismatch, &ClientBaseline{
			PCR14:       stored,
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
