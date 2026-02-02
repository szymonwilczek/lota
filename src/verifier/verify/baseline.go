// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR Baseline Store (TOFU)
//
// Implements Trust On First Use (TOFU) for PCR values.
// On first attestation, PCR 14 (agent self-measurement) is stored as "Known Good".
// Subsequent attestations must match this baseline or fail with INTEGRITY_MISMATCH.

package verify

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// stores known-good measurements for a client
type ClientBaseline struct {
	// agent self-measurement hash
	PCR14 [types.HashSize]byte

	// when baseline was established
	FirstSeen time.Time

	// last successful attestation
	LastSeen time.Time

	// number of successful attestations
	AttestCount uint64
}

// manages per-client PCR baselines (TOFU)
type BaselineStore struct {
	mu        sync.RWMutex
	baselines map[string]*ClientBaseline // clientID -> baseline
}

// creates a new baseline store
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines: make(map[string]*ClientBaseline),
	}
}

// describes the outcome of TOFU check
type TOFUResult int

const (
	// First time seeing this client - baseline established
	TOFUFirstUse TOFUResult = iota

	// PCR matches stored baseline
	TOFUMatch

	// PCR does NOT match stored baseline - TAMPERING!!!
	TOFUMismatch
)

// performs TOFU validation for PCR 14
// returns TOFUFirstUse on first attestation (baseline stored)
// returns TOFUMatch if PCR matches baseline
// returns TOFUMismatch if PCR differs from baseline (CRITICAL!)
func (s *BaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	existing, exists := s.baselines[clientID]
	if !exists {
		// first use - establish baseline
		baseline := &ClientBaseline{
			PCR14:       pcr14,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
		s.baselines[clientID] = baseline
		return TOFUFirstUse, baseline
	}

	if existing.PCR14 != pcr14 {
		// possible tampering
		return TOFUMismatch, existing
	}

	// update last seen
	existing.LastSeen = now
	existing.AttestCount++
	return TOFUMatch, existing
}

// returns the stored baseline for a client (nil if not found)
func (s *BaselineStore) GetBaseline(clientID string) *ClientBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.baselines[clientID]
}

// removes stored baseline for a client
func (s *BaselineStore) ClearBaseline(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.baselines, clientID)
}

// returns all known client IDs
func (s *BaselineStore) ListClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]string, 0, len(s.baselines))
	for id := range s.baselines {
		clients = append(clients, id)
	}
	return clients
}

// returns baseline store statistics
type BaselineStats struct {
	TotalClients   int
	OldestBaseline time.Time
	NewestBaseline time.Time
}

func (s *BaselineStore) Stats() BaselineStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := BaselineStats{
		TotalClients: len(s.baselines),
	}

	for _, b := range s.baselines {
		if stats.OldestBaseline.IsZero() || b.FirstSeen.Before(stats.OldestBaseline) {
			stats.OldestBaseline = b.FirstSeen
		}
		if b.FirstSeen.After(stats.NewestBaseline) {
			stats.NewestBaseline = b.FirstSeen
		}
	}

	return stats
}

// returns hex-encoded PCR 14 value
func FormatPCR14(pcr14 [types.HashSize]byte) string {
	return hex.EncodeToString(pcr14[:])
}
