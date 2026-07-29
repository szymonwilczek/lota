// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
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
	"fmt"
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
//	commit = SHA256(initramfsLockTag)
//	pcr14  = SHA256(baseline || commit)
//
// baseline is the PCR14 content present when the lock helper runs:
// shim MOK measurement (MokList, SbatLevel, MokListRT) on a shim-booted host,
// or 0^32 on a UEFI host that boots without shim, since nothing else measures
// PCR14 before userspace.
//
// Verifier reconstructs baseline from the TPM event log.
//
// resetCount and restartCount are accepted for API symmetry with the
// agent helper, but intentionally ignored. The initramfs lock runs long
// before the quote, so binding it to restartCount would make a correct
// boot fail when the counter moves between initramfs and attestation.
// Freshness is bound by the later agent boot commitment, which still
// includes the TPMS_ATTEST ClockInfo counters.
func DeriveInitramfsLockPCR14(baseline [types.HashSize]byte, resetCount, restartCount uint32) [types.HashSize]byte {
	_, _ = resetCount, restartCount

	commit := sha256.New()
	commit.Write([]byte(initramfsLockTag))
	commitDigest := commit.Sum(nil)

	pcr := sha256.New()
	pcr.Write(baseline[:])
	pcr.Write(commitDigest)

	var out [types.HashSize]byte
	copy(out[:], pcr.Sum(nil))
	return out
}

// DeriveLockedBootCommitmentPCR14 reproduces the final PCR14 value
// when both the initramfs lock and the agent's boot commitment have
// been applied in sequence. The chain is:
//
//	lock_value  = DeriveInitramfsLockPCR14()
//	boot_commit = SHA256(bootCommitmentTag || agentHash || R || S)
//	pcr14_final = SHA256(lock_value || boot_commit)
//
// This is the only PCR14 derivation the verifier validates;
// report that does not carry both FlagInitramfsLockV1 and FlagBootCommitment
// is rejected before the chain is rederived.
func DeriveLockedBootCommitmentPCR14(baseline, agentHash [types.HashSize]byte,
	resetCount, restartCount uint32,
) [types.HashSize]byte {
	lockValue := DeriveInitramfsLockPCR14(baseline, resetCount, restartCount)

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

// pcr14Index is the TPM PCR the LOTA boot-commitment chain anchors in.
// It is also the PCR shim measures the MOK state into on UEFI Secure Boot.
const pcr14Index = 14

// PCR14BaselineFromEventLog reconstructs the PCR14 content present before
// any LOTA extend by replaying the firmware TCG event log.
// On UEFI Secure Boot shim measures the MOK state (MokList, SbatLevel, MokListRT)
// into PCR14 before ExitBootServices;
// LOTA's initramfs-lock and agent extends run afterwards and never enter the
// firmware log, so the replayed PCR14 is exactly the baseline the lock chain
// anchors on.
//
// nil log, replay error, or no PCR14 events yields 0^32 - UEFI host whose boot
// chain never measured PCR14 (no shim).
// The log is proven to be a UEFI one before this runs, see UEFIAnchored.
//
// baseline needs no separate trust:
// it is authenticated by the quote, since forged event log makes Derive*(baseline, ...)
// diverge from the signed PCR14 and the match fails closed
func PCR14BaselineFromEventLog(parsed *ParsedEventLog) [types.HashSize]byte {
	var zero [types.HashSize]byte
	if parsed == nil || pcr14Index >= types.PCRCount {
		return zero
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		return zero
	}
	return replay.PCRValues[pcr14Index]
}

// MatchLockedBootCommitmentPCR14 rederives PCR14 for the agent_hash
// bound at boot and the (resetCount, restartCount) reported in the quote's
// ClockInfo, then scans restartCount backward looking for value whose derivation
// matches the PCR14 carried in the quote.
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
// quoteRestartCount] reproduces the PCR14 carried in target.
//
// expected is set to the matched derivation (drift accepted) or to the exact
// quote derivation (when no candidate matched) so the caller can log
// the failure with a deterministic expected_pcr14 column.
//
// restartDrift carries the positive distance between the quote value
// and the matched value (0 when the exact-match branch succeeded).
//
// The scan does not weaken the integrity binding: an attacker who does
// not know the pinned agent_hash cannot produce a matching PCR14 for
// any restartCount value, and resetCount is not iterated so a post-cold-boot
// state cannot be replayed.
func MatchLockedBootCommitmentPCR14(baseline, agentHash [types.HashSize]byte,
	resetCount, quoteRestartCount uint32,
	target [types.HashSize]byte,
	maxRestartSkew uint32,
) (expected [types.HashSize]byte, restartDrift uint32, matched bool) {
	derive := func(ah [types.HashSize]byte, reset, restart uint32) [types.HashSize]byte {
		return DeriveLockedBootCommitmentPCR14(baseline, ah, reset, restart)
	}
	return matchPCR14(derive, agentHash, resetCount,
		quoteRestartCount, target, maxRestartSkew)
}

// matchPCR14 keeps the restartCount-skew scan separate from the derivation it
// scans over, so future derivation can reuse the same exhaustion logic without
// copy/paste.
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

	// removes all stored baseline state for client:
	// the PCR14 baseline, the PCR0/1/7 boot baseline and the re-anchor bookkeeping.
	// Next attestation re-establishes trust per the active TOFU/policy configuration.
	ClearBaseline(clientID string) error

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

// TenantStorer is optionally implemented by baseline stores that persist
// the CA-assigned device tenant next to the baseline row.
// Tenant is stamped from the verified AIK certificate after every successful
// attestation and partitions the operator-facing surface:
// listings, mutations and logs are scoped to it.
// Row that predates tenancy (or store without the capability) reads as DefaultTenant.
type TenantStorer interface {
	// SetClientTenant records the client's tenant on its baseline row.
	// Fails when the client has no baseline row to stamp.
	SetClientTenant(clientID, tenant string) error

	// ClientTenant returns the recorded tenant.
	// Client without baseline row or with pre-tenancy row is in DefaultTenant.
	ClientTenant(clientID string) (string, error)
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

// ReanchorState is the persisted re-anchor bookkeeping for a client:
// event log captured when the boot baseline was pinned (for PCR 7 replay-diff),
// the firmware version at that time (ESRT anti-rollback), the sticky ESRT-capability
// bit (device that ever reported an ESRT and later stops is suspicious), the last
// assurance tier, and the rate-limit counter.
// Present is false when no baseline row exists for the client.
type ReanchorState struct {
	Present          bool
	EventLogBaseline []byte
	ESRTVersion      uint32
	ESRTCapable      bool
	LFA              bool
	LFAReviewPending bool
	ReanchorCount    int
	LastReanchorAt   time.Time
}

// ReanchorStorer is optionally implemented by baseline stores that support
// self-service re-anchor after a legitimate firmware drift.
//
//   - GetReanchorState returns the bookkeeping for a client (Present == false
//     when the client has no baseline row, which the verifier treats as
//     fail-closed: no event-log baseline means no replay-diff is possible).
//   - ArchiveAndReanchor atomically copies the current PCR0/1/7 row into the
//     archive table and replaces it with boot, recording the new event-log
//     baseline, ESRT version and assurance tier, setting esrt_capable sticky,
//     and bumping reanchor_count / last_reanchor_at. reason labels the archive
//     row ("strong" or "lfa").
//     now is the re-anchor clock: the implementation re-reads last_reanchor_at
//     under the same lock/transaction as the write and returns ErrReanchorRateLimited
//     when now is still within the assurance-tier interval, so concurrent attestations
//     for one client cannot race the cheap-path gate in reanchorDecision.
type ReanchorStorer interface {
	GetReanchorState(clientID string) ReanchorState
	ArchiveAndReanchor(clientID string, boot BootBaseline, eventLog []byte,
		esrtVersion uint32, esrtCapable, lfa bool, reason string,
		now time.Time) error

	// RecordBootEvidence captures the event log and firmware version that
	// accompanied a first-use boot baseline, so a later re-anchor has a
	// reference to replay-diff PCR 7 against.
	// It is an idempotent update on the existing baseline row (no archive,
	// no counter bump) and sets esrt_capable sticky when esrtPresent.
	// Missing call simply leaves the event-log baseline empty, which the
	// verifier treats as fail-closed (operator re-baseline) at re-anchor time.
	RecordBootEvidence(clientID string, eventLog []byte, esrtVersion uint32,
		esrtPresent bool) error

	// ListLFAReviewPending returns the clients that have re-anchored on the
	// Low-Firmware-Assurance path and have not yet been reviewed by an
	// operator.
	// LFA re-anchors apply automatically (no approval gate);
	// this is a post-fact review queue, not a blocking one.
	ListLFAReviewPending() []string

	// AcknowledgeLFAReview clears a client's pending-review flag once an
	// operator has looked at its LFA re-anchor.
	// It does not touch the baseline;
	// it only takes the client off the review list.
	AcknowledgeLFAReview(clientID string) error
}

// manages per-client PCR baselines (TOFU)
type BaselineStore struct {
	mu            sync.RWMutex
	baselines     map[string]*ClientBaseline // clientID -> PCR14 baseline
	bootBaselines map[string]*BootBaseline   // clientID -> PCR0/1/7 baseline
	reanchor      map[string]*ReanchorState  // clientID -> re-anchor state
	tenants       map[string]string          // clientID -> CA-assigned tenant
}

// creates a new baseline store
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines:     make(map[string]*ClientBaseline),
		bootBaselines: make(map[string]*BootBaseline),
		reanchor:      make(map[string]*ReanchorState),
		tenants:       make(map[string]string),
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

// GetReanchorState returns the in-memory re-anchor bookkeeping for a
// client. Present is false when the client has no boot baseline yet.
func (s *BaselineStore) GetReanchorState(clientID string) ReanchorState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.bootBaselines[clientID]; !ok {
		return ReanchorState{}
	}
	st := ReanchorState{Present: true}
	if r, ok := s.reanchor[clientID]; ok {
		st = *r
		st.Present = true
		if r.EventLogBaseline != nil {
			st.EventLogBaseline = append([]byte(nil), r.EventLogBaseline...)
		}
	}
	return st
}

// ArchiveAndReanchor replaces the stored boot baseline with boot and records
// the new re-anchor state.
// In-memory store keeps no archive table; the previous values are simply overwritten
// (durable backends persist the archive).
// esrtCapable is sticky: once true it stays true.
func (s *BaselineStore) ArchiveAndReanchor(clientID string, boot BootBaseline,
	eventLog []byte, esrtVersion uint32, esrtCapable, lfa bool,
	reason string, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	prev := s.reanchor[clientID]
	if prev != nil && !prev.LastReanchorAt.IsZero() &&
		now.Sub(prev.LastReanchorAt) < reanchorInterval(lfa) {
		return ErrReanchorRateLimited
	}

	nb := boot
	nb.FirstSeen = now
	nb.LastSeen = now
	s.bootBaselines[clientID] = &nb

	st := &ReanchorState{Present: true}
	if prev != nil {
		*st = *prev
		st.Present = true
	}
	st.EventLogBaseline = append([]byte(nil), eventLog...)
	st.ESRTVersion = esrtVersion
	st.ESRTCapable = st.ESRTCapable || esrtCapable
	st.LFA = lfa
	if lfa {
		// auto re-anchor; flag for post-fact operator review
		st.LFAReviewPending = true
	}
	st.ReanchorCount++
	st.LastReanchorAt = now
	s.reanchor[clientID] = st
	return nil
}

// RecordBootEvidence stores the event log + ESRT version that accompanied a
// first-use boot baseline (in-memory).
// esrt_capable is sticky.
func (s *BaselineStore) RecordBootEvidence(clientID string, eventLog []byte,
	esrtVersion uint32, esrtPresent bool,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.reanchor[clientID]
	if st == nil {
		st = &ReanchorState{Present: true}
	}
	st.Present = true
	st.EventLogBaseline = append([]byte(nil), eventLog...)
	st.ESRTVersion = esrtVersion
	st.ESRTCapable = st.ESRTCapable || esrtPresent
	s.reanchor[clientID] = st
	return nil
}

// ListLFAReviewPending returns clients with an unreviewed LFA re-anchor
// (in-memory).
func (s *BaselineStore) ListLFAReviewPending() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for id, st := range s.reanchor {
		if st != nil && st.LFAReviewPending {
			out = append(out, id)
		}
	}
	return out
}

// AcknowledgeLFAReview clears a client's pending-review flag (in-memory).
func (s *BaselineStore) AcknowledgeLFAReview(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.reanchor[clientID]; st != nil {
		st.LFAReviewPending = false
	}
	return nil
}

// Removes all stored baseline state for a client.
// SQL-backed stores keep the PCR14, boot-PCR and re-anchor columns in one row,
// so their DELETE drops everything at once.
// Mirror that here across the three maps.
func (s *BaselineStore) ClearBaseline(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.baselines, clientID)
	delete(s.bootBaselines, clientID)
	delete(s.reanchor, clientID)
	delete(s.tenants, clientID)
	return nil
}

// SetClientTenant records the CA-assigned tenant for client that already
// holds baseline row.
func (s *BaselineStore) SetClientTenant(clientID, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.baselines[clientID]; !ok {
		return fmt.Errorf("no baseline row for client %q", clientID)
	}
	s.tenants[clientID] = tenant
	return nil
}

// ClientTenant returns the recorded tenant.
// Client never stamped is in the default tenant.
func (s *BaselineStore) ClientTenant(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tenant, ok := s.tenants[clientID]; ok && tenant != "" {
		return tenant, nil
	}
	return DefaultTenant, nil
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
	currentPCR14, agentHash [types.HashSize]byte,
) (TOFUResult, *ClientBaseline) {
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

	// row without a pinned agent_hash can only come from out-of-band PCR14 pin:
	// every attestation writes the hash.
	// Mismatch branch below therefore also covers it -- the verifier does not
	// adopt whichever hash happens to arrive first.
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
	boot *BootBaseline,
) AttestationOutcome {
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

	switch {
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
