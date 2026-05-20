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

// defines the interface for PCR baseline stores
type BaselineStorer interface {
	// performs TOFU validation for PCR 14
	CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline)

	// returns the stored baseline for a client (nil if not found)
	GetBaseline(clientID string) *ClientBaseline

	// removes stored baseline for a client
	ClearBaseline(clientID string)

	// returns all known client IDs
	ListClients() []string

	// returns baseline store statistics
	Stats() BaselineStats
}

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

// boot-chain PCR values that must remain stable across reboots.
//
// PCR0  - SRTM, CRTM, BIOS / UEFI firmware code
// PCR1  - host platform configuration: SMBIOS, BIOS settings, boot order
// PCR7  - Secure Boot policy and authority chain
//
// Pinned via TOFU on first attestation; any deviation surfaces a
// firmware / SecureBoot / cmdline change to the operator instead of
// silently accepting the new measurements as if they were genuine.
type BootBaseline struct {
	PCR0 [types.HashSize]byte
	PCR1 [types.HashSize]byte
	PCR7 [types.HashSize]byte

	// timestamps mirror ClientBaseline semantics
	FirstSeen time.Time
	LastSeen  time.Time
}

// BootBaselineStorer is optionally implemented by baseline stores that
// pin firmware / SecureBoot PCRs in addition to PCR14. Callers should
// type-assert and degrade to PCR14-only validation if not satisfied.
type BootBaselineStorer interface {
	// CheckAndUpdateBootPCRs validates PCR0/PCR1/PCR7 against the stored
	// baseline. Semantics mirror BaselineStorer.CheckAndUpdate.
	CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline)
}

// manages per-client PCR baselines (TOFU)
type BaselineStore struct {
	mu            sync.RWMutex
	baselines     map[string]*ClientBaseline // clientID -> PCR14 baseline
	bootBaselines map[string]*BootBaseline   // clientID -> PCR0/1/7 baseline
}

// creates a new baseline store
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines:     make(map[string]*ClientBaseline),
		bootBaselines: make(map[string]*BootBaseline),
	}
}

// describes the outcome of TOFU check
type TOFUResult int

const (
	// First time seeing this client - baseline established
	TOFUFirstUse TOFUResult = iota

	// PCR matches stored baseline
	TOFUMatch

	// PCR does NOT match stored baseline - possible tampering
	TOFUMismatch

	// Database or store error - must not be treated as first use
	TOFUError
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

// CheckAndUpdateBootPCRs pins PCR0/PCR1/PCR7 with TOFU semantics that
// mirror CheckAndUpdate(). Any deviation from the stored boot baseline
// surfaces a firmware / SecureBoot / boot-order change.
func (s *BaselineStore) CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	existing, exists := s.bootBaselines[clientID]
	if !exists {
		stored := boot
		stored.FirstSeen = now
		stored.LastSeen = now
		s.bootBaselines[clientID] = &stored
		out := stored
		return TOFUFirstUse, &out
	}

	if existing.PCR0 != boot.PCR0 || existing.PCR1 != boot.PCR1 || existing.PCR7 != boot.PCR7 {
		out := *existing
		return TOFUMismatch, &out
	}

	existing.LastSeen = now
	out := *existing
	return TOFUMatch, &out
}
