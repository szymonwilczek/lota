// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR Baseline Store (TOFU)
//
// Implements Trust On First Use (TOFU) for PCR values.
// On first attestation, PCR 14 (agent self-measurement) is stored as "Known Good".
// Subsequent attestations must match this baseline or fail with INTEGRITY_MISMATCH.

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// bootCommitmentTag is the domain-separation prefix used by the agent
// when extending PCR14 with the boot commitment. It MUST match the
// LOTA-PCR14-BOOT-COMMITMENT-v1 string in src/agent/tpm.c.
const bootCommitmentTag = "LOTA-PCR14-BOOT-COMMITMENT-v1"

// initramfsLockTag is the domain-separation prefix used by the
// initramfs lock helper (src/initramfs/lota-pcr14-lock.c) when it
// extends PCR14 before any userspace daemon runs. The verifier
// rederives the same digest whenever FlagInitramfsLockV1 is set on a
// report.
const initramfsLockTag = "LOTA-PCR14-INITRAMFS-LOCK-v1"

// DeriveInitramfsLockPCR14 reproduces the post-extend PCR14 value the
// initramfs lock helper installs:
//
//	commit = SHA256(initramfsLockTag || resetCount_be || restartCount_be)
//	pcr14  = SHA256(0^32 || commit)
//
// resetCount and restartCount are taken from the TPMS_ATTEST ClockInfo
// of the quote. The helper does NOT include agent_hash in the digest:
// the lock runs before the agent binary is on the running system, so
// no self_hash exists yet, and binding the lock only to the TPM
// counters keeps the derivation reproducible regardless of which
// agent binary later layers a boot commitment on top.
func DeriveInitramfsLockPCR14(resetCount, restartCount uint32) [types.HashSize]byte {
	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], resetCount)
	binary.BigEndian.PutUint32(counters[4:8], restartCount)

	commit := sha256.New()
	commit.Write([]byte(initramfsLockTag))
	commit.Write(counters[:])
	commitDigest := commit.Sum(nil)

	var zero [types.HashSize]byte
	pcr := sha256.New()
	pcr.Write(zero[:])
	pcr.Write(commitDigest)

	var out [types.HashSize]byte
	copy(out[:], pcr.Sum(nil))
	return out
}

// DeriveLockedBootCommitmentPCR14 reproduces the final PCR14 value
// when both the initramfs lock and the agent's boot commitment have
// been applied in sequence. The chain is:
//
//	lock_value  = DeriveInitramfsLockPCR14(R, S)
//	boot_commit = SHA256(bootCommitmentTag || agentHash || R || S)
//	pcr14_final = SHA256(lock_value || boot_commit)
//
// The verifier picks this derivation when the report carries
// FlagInitramfsLockV1 alongside FlagBootCommitment; a report with
// only FlagBootCommitment falls back to DeriveBootCommitmentPCR14.
func DeriveLockedBootCommitmentPCR14(agentHash [types.HashSize]byte,
	resetCount, restartCount uint32) [types.HashSize]byte {

	lockValue := DeriveInitramfsLockPCR14(resetCount, restartCount)

	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], resetCount)
	binary.BigEndian.PutUint32(counters[4:8], restartCount)

	commit := sha256.New()
	commit.Write([]byte(bootCommitmentTag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	commitDigest := commit.Sum(nil)

	pcr := sha256.New()
	pcr.Write(lockValue[:])
	pcr.Write(commitDigest)

	var out [types.HashSize]byte
	copy(out[:], pcr.Sum(nil))
	return out
}

// DeriveBootCommitmentPCR14 reproduces the agent's PCR14 derivation:
//
//	commit  = SHA256(tag || agent_hash || resetCount_be || restartCount_be)
//	pcr14   = SHA256(0^32 || commit)
//
// resetCount and restartCount are taken from the TPMS_ATTEST ClockInfo
// of the quote.
func DeriveBootCommitmentPCR14(agentHash [types.HashSize]byte,
	resetCount, restartCount uint32) [types.HashSize]byte {

	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], resetCount)
	binary.BigEndian.PutUint32(counters[4:8], restartCount)

	commit := sha256.New()
	commit.Write([]byte(bootCommitmentTag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	commitDigest := commit.Sum(nil)

	var zero [types.HashSize]byte
	pcr := sha256.New()
	pcr.Write(zero[:])
	pcr.Write(commitDigest)

	var out [types.HashSize]byte
	copy(out[:], pcr.Sum(nil))
	return out
}

// MatchBootCommitmentPCR14 rederives PCR14 for the agent_hash bound at
// boot and the (resetCount, restartCount) reported in the quote's
// ClockInfo, then scans restartCount backward looking for a value whose
// derivation matches the PCR14 carried in the quote.
//
// The scan exists because the agent extends PCR14 once at startup using
// the restartCount in effect at that moment, while the quote carries
// the restartCount in effect when it is signed. TPM2_Startup(STATE)
// increments restartCount across every suspend/resume cycle within a
// single boot session, so on laptops the two values diverge between
// attestations. resetCount is left fixed because the TPM only
// increments it at TPM_INIT (cold boot), which would also have killed
// the agent process and triggered a fresh extend on the next start.
//
// matched is true when some restartCount in [quoteRestartCount-maxRestartSkew,
// quoteRestartCount] reproduces the PCR14 carried in target. expected
// is set to the matched derivation (drift accepted) or to the exact
// quote derivation (when no candidate matched) so the caller can log
// the failure with a deterministic expected_pcr14 column.
// restartDrift carries the positive distance between the quote value
// and the matched value (0 when the exact-match branch succeeded).
//
// The scan does not weaken the integrity binding: an attacker who does
// not know the pinned agent_hash cannot produce a matching PCR14 for
// any restartCount value, and resetCount is not iterated so a post-cold-boot
// state cannot be replayed.
func MatchBootCommitmentPCR14(agentHash [types.HashSize]byte,
	resetCount, quoteRestartCount uint32,
	target [types.HashSize]byte,
	maxRestartSkew uint32,
) (expected [types.HashSize]byte, restartDrift uint32, matched bool) {

	return matchPCR14(DeriveBootCommitmentPCR14, agentHash, resetCount,
		quoteRestartCount, target, maxRestartSkew)
}

// MatchLockedBootCommitmentPCR14 mirrors MatchBootCommitmentPCR14 for
// the two-hop derivation used when an initramfs lock has run before
// the agent. The skew-tolerant scan stays the same; only the per-step
// derivation function differs so a caller dispatching on
// FlagInitramfsLockV1 selects the right chain.
func MatchLockedBootCommitmentPCR14(agentHash [types.HashSize]byte,
	resetCount, quoteRestartCount uint32,
	target [types.HashSize]byte,
	maxRestartSkew uint32,
) (expected [types.HashSize]byte, restartDrift uint32, matched bool) {

	return matchPCR14(DeriveLockedBootCommitmentPCR14, agentHash, resetCount,
		quoteRestartCount, target, maxRestartSkew)
}

// matchPCR14 factors the restartCount-skew scan out of the two
// derivation paths so a future third derivation (e.g. a v2 lock) can
// reuse the same exhaustion logic without copy/paste.
func matchPCR14(
	derive func(agentHash [types.HashSize]byte, reset, restart uint32) [types.HashSize]byte,
	agentHash [types.HashSize]byte,
	resetCount, quoteRestartCount uint32,
	target [types.HashSize]byte,
	maxRestartSkew uint32,
) (expected [types.HashSize]byte, restartDrift uint32, matched bool) {

	expected = derive(agentHash, resetCount, quoteRestartCount)
	if expected == target {
		return expected, 0, true
	}
	for d := uint32(1); d <= maxRestartSkew && d <= quoteRestartCount; d++ {
		cand := derive(agentHash, resetCount, quoteRestartCount-d)
		if cand == target {
			return cand, d, true
		}
	}
	return expected, 0, false
}

// ErrBaselineNotFound is returned by baseline-mutating helpers when the
// target client has no PCR14 baseline row yet.
var ErrBaselineNotFound = errors.New("baseline not found for client")

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

	// SHA-256 of the agent binary; pinned independently of PCR14 so the
	// expected PCR14 can be derived from (agent_hash, resetCount,
	// restartCount) and replayed-but-stale PCR14 values are rejected
	// after a dirty reboot.
	//
	// Zero array means the baseline was created by an older verifier
	// that did not pin agent_hash; subsequent attestations from the
	// same client backfill the field on success.
	AgentHash [types.HashSize]byte

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

// BootBaselineReader is implemented by baseline stores that can return
// the persisted PCR0/PCR1/PCR7 baseline for a client without performing
// a TOFU write. The verifier uses it to gate first-use boot baselines
// behind an enrollment ceremony: if no baseline row exists and the
// active policy does not pin PCR0/PCR1/PCR7 explicitly, the production
// configuration refuses the attestation instead of TOFU-establishing
// whatever firmware/Secure Boot values the agent ships up. A nil
// return is the canonical "not enrolled" signal.
type BootBaselineReader interface {
	GetBootBaseline(clientID string) *BootBaseline
}

// AgentHashStorer is optionally implemented by baseline stores that can
// pin the agent self-hash alongside (or instead of) PCR14. The hash is
// the SHA-256 of the agent binary as captured by the agent at startup;
// the verifier uses it to derive the expected PCR14 from TPM ClockInfo,
// defeating dirty-shutdown replay against the static PCR14 baseline.
type AgentHashStorer interface {
	// CheckAndUpdateAgentHash pins the agent self-hash with TOFU
	// semantics that mirror CheckAndUpdate(). currentPCR14 is recorded
	// alongside the hash so the baselines table satisfies its NOT NULL
	// constraint on first use.
	CheckAndUpdateAgentHash(clientID string,
		currentPCR14, agentHash [types.HashSize]byte) (TOFUResult, *ClientBaseline)
}

// AttestationOutcome is the result of a single AtomicBaselineStorer
// transaction. The two TOFU results report the per-component decision;
// the snapshots carry whichever baseline values the caller needs to
// surface in security logs or pass back to the agent. BootProvided
// mirrors the caller's intent so consumers can distinguish "boot
// pin not supplied this round" from "boot pin succeeded silently".
type AttestationOutcome struct {
	AgentHashResult   TOFUResult
	AgentHashBaseline *ClientBaseline
	BootProvided      bool
	BootResult        TOFUResult
	BootBaseline      *BootBaseline
}

// AtomicBaselineStorer is implemented by baseline stores that can
// commit both the agent_hash pin and the firmware/SecureBoot PCR pin
// in a single read-modify-write transaction. Splitting the two writes
// into successive AgentHashStorer + BootBaselineStorer calls opens a
// race in multi-process verifier deployments: one process can finish
// the PCR14/agent_hash insert and a second process can sneak in
// between with a CheckAndUpdateBootPCRs that sees the row without the
// boot columns yet and TOFU-establishes attacker-controlled
// PCR0/PCR1/PCR7. The combined transaction closes the window by
// taking an exclusive write lock for the entire decision.
//
// The contract is the same as the split methods:
//   - agentHash is always evaluated;
//   - boot, when non-nil, is evaluated in the same critical section;
//     when nil, the boot columns are left untouched and
//     AttestationOutcome.BootProvided is false on return;
//   - any mismatch leaves persistent state unchanged so the caller's
//     reject path matches the pre-transaction view.
type AtomicBaselineStorer interface {
	CheckAndUpdateAttestation(clientID string,
		pcr14, agentHash [types.HashSize]byte,
		boot *BootBaseline) AttestationOutcome
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

	// TOFULegacyBackfill is returned by CheckAndUpdateAgentHash when a
	// pre-existing baseline row carries no pinned agent_hash and the
	// store accepts the incoming value as the canonical one. The
	// transition can only happen once per client (subsequent rounds
	// take the TOFUMatch / TOFUMismatch branch), but the row is
	// indistinguishable from a real first-use after the write, so the
	// verifier surfaces a security event and operators can opt to
	// refuse the implicit trust upgrade via
	// VerifierConfig.RejectLegacyBaselines.
	TOFULegacyBackfill
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

// GetBootBaseline returns the persisted PCR0/PCR1/PCR7 row for a
// client or nil when the boot baseline has never been pinned. It is
// the read-only side of BootBaselineStorer and never writes.
func (s *BaselineStore) GetBootBaseline(clientID string) *BootBaseline {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bootBaselines[clientID]
	if !ok {
		return nil
	}
	out := *b
	return &out
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

// CheckAndUpdateAgentHash pins agent_hash with TOFU semantics in the
// in-memory baseline store; currentPCR14 is captured on first use so
// operators retain a forensic snapshot of the runtime PCR value.
func (s *BaselineStore) CheckAndUpdateAgentHash(clientID string,
	currentPCR14, agentHash [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	existing, exists := s.baselines[clientID]
	if !exists {
		b := &ClientBaseline{
			PCR14:       currentPCR14,
			AgentHash:   agentHash,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
		s.baselines[clientID] = b
		out := *b
		return TOFUFirstUse, &out
	}

	var zero [types.HashSize]byte
	if existing.AgentHash == zero {
		// Legacy row from a pre-FlagBootCommitment attestation: the
		// PCR14 baseline is pinned but agent_hash is not. Record the
		// incoming hash so future rounds can verify it, but report the
		// transition as TOFULegacyBackfill so the caller can audit
		// (and, when configured, reject) the implicit trust upgrade.
		existing.AgentHash = agentHash
		existing.LastSeen = now
		existing.AttestCount++
		out := *existing
		return TOFULegacyBackfill, &out
	}

	if existing.AgentHash != agentHash {
		out := *existing
		return TOFUMismatch, &out
	}

	existing.LastSeen = now
	existing.AttestCount++
	out := *existing
	return TOFUMatch, &out
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

// CheckAndUpdateAttestation commits the agent_hash pin and (when boot
// is non-nil) the firmware/SecureBoot pin in a single critical
// section, matching the SQLite store's BEGIN IMMEDIATE contract on a
// process-local map. The in-memory store does not face the
// multi-process race that motivated the interface, but exposing the
// combined call keeps the verifier wiring uniform across stores so
// tests and production share one decision path.
//
// Mismatch in either component leaves the existing baseline
// untouched, mirroring the SQLite implementation.
func (s *BaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline) AttestationOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	outcome := AttestationOutcome{BootProvided: boot != nil}

	// --- agent_hash branch ---
	existing, exists := s.baselines[clientID]
	if !exists {
		b := &ClientBaseline{
			PCR14:       pcr14,
			AgentHash:   agentHash,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
		// snapshot first; row not committed yet in case boot mismatches.
		snap := *b
		outcome.AgentHashResult = TOFUFirstUse
		outcome.AgentHashBaseline = &snap

		// boot branch on a fresh row mirrors the agent_hash decision:
		// any incoming boot baseline becomes the canonical pin.
		if boot != nil {
			stored := *boot
			stored.FirstSeen = now
			stored.LastSeen = now
			outcome.BootResult = TOFUFirstUse
			bootSnap := stored
			outcome.BootBaseline = &bootSnap
			s.bootBaselines[clientID] = &stored
		}
		s.baselines[clientID] = b
		return outcome
	}

	var zero [types.HashSize]byte
	switch {
	case existing.AgentHash == zero:
		// legacy row backfill - tentative until the boot decision below.
		outcome.AgentHashResult = TOFULegacyBackfill
	case existing.AgentHash != agentHash:
		// agent_hash mismatch terminates the transaction: leave the row
		// untouched and return the stored snapshot for security logging.
		snap := *existing
		outcome.AgentHashResult = TOFUMismatch
		outcome.AgentHashBaseline = &snap
		if boot != nil {
			// boot side carries no decision because no write happens.
			outcome.BootResult = TOFUError
		}
		return outcome
	default:
		outcome.AgentHashResult = TOFUMatch
	}

	// --- boot branch ---
	if boot != nil {
		existingBoot, hasBoot := s.bootBaselines[clientID]
		if !hasBoot {
			outcome.BootResult = TOFUFirstUse
		} else if existingBoot.PCR0 != boot.PCR0 ||
			existingBoot.PCR1 != boot.PCR1 ||
			existingBoot.PCR7 != boot.PCR7 {
			// boot mismatch: undo any tentative state and return.
			snap := *existing
			outcome.AgentHashBaseline = &snap
			snapBoot := *existingBoot
			outcome.BootResult = TOFUMismatch
			outcome.BootBaseline = &snapBoot
			return outcome
		} else {
			outcome.BootResult = TOFUMatch
		}
	}

	// --- commit phase: both components passed ---
	if outcome.AgentHashResult == TOFULegacyBackfill {
		existing.AgentHash = agentHash
	}
	existing.LastSeen = now
	existing.AttestCount++
	snap := *existing
	outcome.AgentHashBaseline = &snap

	if boot != nil {
		switch outcome.BootResult {
		case TOFUFirstUse:
			stored := *boot
			stored.FirstSeen = now
			stored.LastSeen = now
			s.bootBaselines[clientID] = &stored
			snapBoot := stored
			outcome.BootBaseline = &snapBoot
		case TOFUMatch:
			existingBoot := s.bootBaselines[clientID]
			existingBoot.LastSeen = now
			snapBoot := *existingBoot
			outcome.BootBaseline = &snapBoot
		}
	}

	return outcome
}
