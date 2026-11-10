// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - per-client baselines pinned on first use

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// bootCommitmentTag is the domain-separation prefix of the agent's PCR 14
// boot commitment. It must match TPM_BOOT_COMMITMENT_TAG in src/agent/tpm.c.
const bootCommitmentTag = "LOTA-PCR14-BOOT-COMMITMENT-v1"

// initramfsLockTag is the domain-separation prefix of the PCR 14 extend by
// the initramfs lock helper (src/initramfs/lota-pcr14-lock.c).
const initramfsLockTag = "LOTA-PCR14-INITRAMFS-LOCK-v1"

// DeriveInitramfsLockPCR14 reproduces the post-extend PCR14 value the
// initramfs lock helper installs:
//
//	commit = SHA256(initramfsLockTag)
//	pcr14  = SHA256(baseline || commit)
//
// baseline is PCR14 when the lock helper runs, as the event log replays it:
// the shim MOK events on a shim-booted host, 0^32 where nothing measured
// PCR14.
func DeriveInitramfsLockPCR14(baseline [types.HashSize]byte) [types.HashSize]byte {
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
//	boot_commit = SHA256(bootCommitmentTag || agentHash)
//	pcr14_final = SHA256(lock_value || boot_commit)
func DeriveLockedBootCommitmentPCR14(baseline, agentHash [types.HashSize]byte) [types.HashSize]byte {
	lockValue := DeriveInitramfsLockPCR14(baseline)

	commit := sha256.New()
	commit.Write([]byte(bootCommitmentTag))
	commit.Write(agentHash[:])
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

// PCR14BaselineFromEventLog replays the firmware event log and returns PCR14
// as it stood before any LOTA extend: LOTA's extends never enter that log.
// A nil log, a replay error or a log with no PCR14 events yields 0^32.
//
// The quote authenticates the result: a forged log makes the derived PCR14
// diverge from the signed one.
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

// MatchLockedBootCommitmentPCR14 derives PCR14 for baseline and agentHash
// and compares it with target, the register the quote signed.
func MatchLockedBootCommitmentPCR14(baseline, agentHash [types.HashSize]byte,
	target [types.HashSize]byte,
) (expected [types.HashSize]byte, matched bool) {
	expected = DeriveLockedBootCommitmentPCR14(baseline, agentHash)
	return expected, expected == target
}

// BaselineStorer is a store of per-client baselines.
type BaselineStorer interface {
	// CheckAndUpdate pins pcr14 for a client with no baseline,
	// else compares it with the pinned PCR14 and counts a match.
	CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline)

	// GetBaseline returns the client's baseline, nil when it has none.
	// A store failure is an error, never a missing baseline.
	GetBaseline(clientID string) (*ClientBaseline, error)

	// ClearBaseline removes the client's baseline. Archived baselines stay.
	ClearBaseline(clientID string) error

	ListClients() []string

	Stats() BaselineStats
}

// PagedClientLister is implemented by baseline stores that can page
// the client listing in one query.
type PagedClientLister interface {
	ListClientsPage(limit, offset int) ([]string, error)
}

// ClientBaseline is the pinned PCR14 and agent hash of a client.
type ClientBaseline struct {
	PCR14 [types.HashSize]byte

	// SHA-256 of the agent binary. Zero is a row from an out-of-band
	// PCR14 pin: the verifier refuses it and never fills it from a report.
	AgentHash [types.HashSize]byte

	FirstSeen time.Time

	LastSeen time.Time

	AttestCount uint64

	// Moves of the pinned agent hash and the time of the last one, the rate
	// limit of ArchiveAndRepinAgentHash. A zero LastAgentHashRepinAt leaves
	// the first move unlimited.
	AgentHashRepinCount  int
	LastAgentHashRepinAt time.Time
}

// BootBaseline is the pinned PCR0 (firmware code), PCR1 (platform
// configuration) and PCR7 (Secure Boot policy) of a client.
type BootBaseline struct {
	PCR0 [types.HashSize]byte
	PCR1 [types.HashSize]byte
	PCR7 [types.HashSize]byte

	FirstSeen time.Time
	LastSeen  time.Time
}

// BootBaselineStorer is implemented by baseline stores that pin PCR0, PCR1
// and PCR7. The verifier refuses to attest against a store without it.
type BootBaselineStorer interface {
	// CheckAndUpdateBootPCRs is CheckAndUpdate for PCR0, PCR1 and PCR7.
	CheckAndUpdateBootPCRs(clientID string, boot BootBaseline) (TOFUResult, *BootBaseline)
}

// BootBaselineReader is implemented by baseline stores that read a client's
// boot baseline without writing it. GetBootBaseline returns nil for a client
// with none, an error on a store failure. Under RequireBootEnrollment a
// stored boot baseline enrolls the client.
type BootBaselineReader interface {
	GetBootBaseline(clientID string) (*BootBaseline, error)
}

// TenantStorer is implemented by baseline stores that keep the CA-assigned
// tenant on the baseline row. Listings, mutations and logs are scoped to it.
type TenantStorer interface {
	// SetClientTenant records the client's tenant on its baseline row.
	// Fails when the client has no baseline row to stamp.
	SetClientTenant(clientID, tenant string) error

	// ClientTenant returns the recorded tenant, DefaultTenant for a client
	// with none.
	ClientTenant(clientID string) (string, error)
}

// AgentHashStorer is implemented by baseline stores that pin the agent hash
// next to PCR14.
type AgentHashStorer interface {
	// CheckAndUpdateAgentHash is CheckAndUpdate for the agent hash.
	// currentPCR14 fills the row's PCR14 on first use, which the schema
	// requires.
	CheckAndUpdateAgentHash(clientID string,
		currentPCR14, agentHash [types.HashSize]byte) (TOFUResult, *ClientBaseline)
}

// AttestationOutcome is the result of CheckAndUpdateAttestation: a TOFU
// result per component and copies of the baselines. BootProvided is whether
// the caller passed a boot baseline. PCR14Result and BootResult read
// TOFUError when the transaction ended before them.
type AttestationOutcome struct {
	AgentHashResult   TOFUResult
	AgentHashBaseline *ClientBaseline
	PCR14Result       TOFUResult
	BootProvided      bool
	BootResult        TOFUResult
	BootBaseline      *BootBaseline
}

// AtomicBaselineStorer is implemented by baseline stores that decide the
// agent hash, PCR14 and boot pins of one attestation under one write lock,
// so a concurrent attestation cannot pin PCR0, PCR1 and PCR7 between them.
// A nil boot leaves the boot baseline untouched. Any mismatch writes nothing.
// With consent, a first boot pin spends the client's forced re-anchor consent
// in the same transaction; with no consent left it writes nothing and reads
// TOFUError.
type AtomicBaselineStorer interface {
	CheckAndUpdateAttestation(clientID string,
		pcr14, agentHash [types.HashSize]byte,
		boot *BootBaseline, consent bool) AttestationOutcome
}

// ReanchorState is a client's re-anchor bookkeeping: the event log captured
// with the boot baseline, the ESRT firmware version then, whether an ESRT was
// ever reported, the last assurance tier, the review flag and the rate-limit
// counter. Present is false when the client has no boot baseline.
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

// ReanchorStorer is implemented by baseline stores that re-anchor a client's
// boot baseline after a firmware drift.
//
//   - GetReanchorState returns the bookkeeping for a client.
//   - ArchiveAndReanchor atomically copies the current PCR0/1/7 row into the
//     archive table and replaces it with boot, recording the new event-log
//     baseline, ESRT version and assurance tier, setting esrt_capable sticky,
//     and bumping reanchor_count / last_reanchor_at. reason labels the archive
//     row ("strong" or "lfa").
//     It re-reads last_reanchor_at under the lock of the write and returns
//     ErrReanchorRateLimited when now is inside the assurance-tier interval,
//     so concurrent attestations of one client cannot race the gate in
//     reanchorDecision.
type ReanchorStorer interface {
	GetReanchorState(clientID string) ReanchorState
	ArchiveAndReanchor(clientID string, boot BootBaseline, eventLog []byte,
		esrtVersion uint32, esrtCapable, lfa bool, reason string,
		now time.Time) error

	// RecordBootEvidence captures the event log and firmware version that
	// accompanied a first-use boot baseline, so a later re-anchor has a
	// reference to replay-diff PCR 7 against.
	// It updates the existing baseline row in place and sets esrt_capable
	// sticky when esrtPresent. Without it a re-anchor escalates to the
	// operator.
	RecordBootEvidence(clientID string, eventLog []byte, esrtVersion uint32,
		esrtPresent bool) error

	// ListLFAReviewPending returns the clients with an applied LFA
	// re-anchor no operator has reviewed.
	ListLFAReviewPending() []string

	// AcknowledgeLFAReview takes the client off the review list, leaving
	// the baseline alone. It returns ErrNoReviewPending when nothing is
	// queued.
	AcknowledgeLFAReview(clientID string) error
}

// ErrNoReviewPending reports a client with no LFA re-anchor awaiting review.
var ErrNoReviewPending = errors.New("no re-anchor review pending")

// AgentHashRepinState is the per-client bookkeeping behind the agent-hash
// re-pin rate limit.
// Present is false when the client has no baseline row.
// Pinned is false when the row has no agent_hash (out-of-band PCR 14 pin);
// such a row has no pin to move.
type AgentHashRepinState struct {
	Present     bool
	Pinned      bool
	RepinCount  int
	LastRepinAt time.Time
}

// ForcedReanchorStorer is optionally implemented by baseline stores that keep
// an operator's forced re-anchor as a one-time consent: under
// RequireBootEnrollment the client's next attestation pins PCR 0/1/7 afresh.
// The consent outlives ClearBaseline and is spent by the attestation that
// pins with it.
type ForcedReanchorStorer interface {
	// MarkForcedReanchor records the consent for clientID.
	MarkForcedReanchor(clientID string) error
	// HasForcedReanchor reports whether clientID holds the consent.
	HasForcedReanchor(clientID string) (bool, error)
	// TakeForcedReanchor removes the consent; true when there was one.
	TakeForcedReanchor(clientID string) (bool, error)
}

// KernelHashRecorder is optionally implemented by baseline stores that keep
// the kernel hash a client last reported.
//
// Advisory: gates nothing and no policy pins it. It is folded into the digest
// the TPM signs, so a stored value is attested and shows whether a device's
// kernel changed. A store without the capability omits it.
type KernelHashRecorder interface {
	// RecordKernelHash stores the reported hash and returns the one it replaced.
	// had is false for a client with no baseline row: a first attestation
	// is not a change.
	RecordKernelHash(clientID string, kernelHash [types.HashSize]byte) (prev [types.HashSize]byte, had bool, err error)
}

// MachineKeysRecorder is optionally implemented by baseline stores that keep
// the keys a client's machine last reported, as MachineKeys JSON.
//
// Advisory: gates nothing. A store without the capability omits them.
type MachineKeysRecorder interface {
	// RecordMachineKeys stores the keys and returns the ones they replaced.
	// A client with no baseline row is not tracked. prev is nil when nothing
	// was stored yet, so a first attestation is not a change.
	RecordMachineKeys(clientID string, keys []byte) (prev []byte, err error)
	// GetMachineKeys returns the stored keys, nil when there are none.
	GetMachineKeys(clientID string) []byte
}

// AgentHashRepinStorer is implemented by baseline stores that move a client's
// pinned agent hash to a build the policy's agent_hashes allow-list names.
//
//   - GetAgentHashRepinState returns the bookkeeping for a client.
//   - ArchiveAndRepinAgentHash atomically copies the outgoing hash into
//     the archive table, replaces the pinned agent_hash and PCR14 with the
//     reported pair and bumps the repin count and time. It re-reads the
//     repin time under the lock of the write and returns
//     ErrAgentHashRepinRateLimited when now is inside
//     AgentHashRepinMinInterval, so concurrent attestations of one client
//     cannot race the gate in agentHashDecision.
type AgentHashRepinStorer interface {
	GetAgentHashRepinState(clientID string) AgentHashRepinState
	ArchiveAndRepinAgentHash(clientID string,
		agentHash, pcr14 [types.HashSize]byte, now time.Time) error
}

// BaselineStore is the in-memory baseline store.
type BaselineStore struct {
	mu            sync.RWMutex
	baselines     map[string]*ClientBaseline // clientID -> PCR14 baseline
	bootBaselines map[string]*BootBaseline   // clientID -> PCR0/1/7 baseline
	reanchor      map[string]*ReanchorState  // clientID -> re-anchor state
	tenants       map[string]string          // clientID -> CA-assigned tenant
	kernelHashes  map[string][types.HashSize]byte
	machineKeys   map[string][]byte
	forced        map[string]struct{} // clientID -> forced consent
}

// NewBaselineStore returns an empty in-memory baseline store.
func NewBaselineStore() *BaselineStore {
	return &BaselineStore{
		baselines:     make(map[string]*ClientBaseline),
		bootBaselines: make(map[string]*BootBaseline),
		reanchor:      make(map[string]*ReanchorState),
		tenants:       make(map[string]string),
		kernelHashes:  make(map[string][types.HashSize]byte),
		machineKeys:   make(map[string][]byte),
		forced:        make(map[string]struct{}),
	}
}

// TOFUResult is the outcome of a check against a pinned value.
type TOFUResult int

const (
	// TOFUFirstUse means nothing was pinned and the reported value now is.
	TOFUFirstUse TOFUResult = iota

	// TOFUMatch means the reported value equals the pinned one.
	TOFUMatch

	// TOFUMismatch means the reported value differs from the pinned one.
	TOFUMismatch

	// TOFUError means the store failed; it is never a first use.
	TOFUError
)

// CheckAndUpdate implements BaselineStorer.
func (s *BaselineStore) CheckAndUpdate(clientID string, pcr14 [types.HashSize]byte) (TOFUResult, *ClientBaseline) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	existing, exists := s.baselines[clientID]
	if !exists {
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
		return TOFUMismatch, existing
	}

	existing.LastSeen = now
	existing.AttestCount++
	return TOFUMatch, existing
}

// GetBaseline implements BaselineStorer.
func (s *BaselineStore) GetBaseline(clientID string) (*ClientBaseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.baselines[clientID], nil
}

// GetBootBaseline implements BootBaselineReader with a copy.
func (s *BaselineStore) GetBootBaseline(clientID string,
) (*BootBaseline, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bootBaselines[clientID]
	if !ok {
		return nil, nil
	}
	out := *b
	return &out, nil
}

// GetReanchorState implements ReanchorStorer. Present is false when the
// client has no boot baseline.
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

// ArchiveAndReanchor implements ReanchorStorer with no archive.
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
	st.LFAReviewPending = lfa
	st.ReanchorCount++
	st.LastReanchorAt = now
	s.reanchor[clientID] = st
	return nil
}

// GetAgentHashRepinState implements AgentHashRepinStorer.
func (s *BaselineStore) GetAgentHashRepinState(clientID string) AgentHashRepinState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.baselines[clientID]
	if !ok {
		return AgentHashRepinState{}
	}
	return AgentHashRepinState{
		Present:     true,
		Pinned:      b.AgentHash != [types.HashSize]byte{},
		RepinCount:  b.AgentHashRepinCount,
		LastRepinAt: b.LastAgentHashRepinAt,
	}
}

// ArchiveAndRepinAgentHash implements AgentHashRepinStorer with no archive.
// Refuses a client with no baseline row and a row with no agent hash.
func (s *BaselineStore) ArchiveAndRepinAgentHash(clientID string,
	agentHash, pcr14 [types.HashSize]byte, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.baselines[clientID]
	if !ok {
		return errors.New("agent-hash re-pin: no baseline row for client")
	}
	if b.AgentHash == ([types.HashSize]byte{}) {
		return ErrAgentHashNotPinned
	}
	if !b.LastAgentHashRepinAt.IsZero() &&
		now.Sub(b.LastAgentHashRepinAt) < AgentHashRepinMinInterval {
		return ErrAgentHashRepinRateLimited
	}

	b.AgentHash = agentHash
	b.PCR14 = pcr14
	b.LastSeen = now
	b.AgentHashRepinCount++
	b.LastAgentHashRepinAt = now
	return nil
}

// RepinPCR14 moves the pinned PCR 14 and the boot evidence (in-memory).
func (s *BaselineStore) RepinPCR14(clientID string,
	from, to [types.HashSize]byte, eventLog []byte, now time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.baselines[clientID]
	if !ok {
		return errors.New("PCR 14 re-pin: no baseline row for client")
	}
	if b.PCR14 != from {
		return ErrPCR14RepinRaced
	}
	st := s.reanchor[clientID]
	if st == nil {
		st = &ReanchorState{}
		s.reanchor[clientID] = st
	}
	b.PCR14 = to
	b.LastSeen = now
	st.Present = true
	st.EventLogBaseline = append([]byte(nil), eventLog...)
	return nil
}

// RecordBootEvidence implements ReanchorStorer.
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

// ListLFAReviewPending implements ReanchorStorer.
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

// AcknowledgeLFAReview implements ReanchorStorer.
func (s *BaselineStore) AcknowledgeLFAReview(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.reanchor[clientID]
	if st == nil || !st.LFAReviewPending {
		return ErrNoReviewPending
	}
	st.LFAReviewPending = false
	return nil
}

// ClearBaseline implements BaselineStorer.
func (s *BaselineStore) ClearBaseline(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.baselines, clientID)
	delete(s.bootBaselines, clientID)
	delete(s.reanchor, clientID)
	delete(s.tenants, clientID)
	delete(s.kernelHashes, clientID)
	delete(s.machineKeys, clientID)
	return nil
}

// MarkForcedReanchor implements ForcedReanchorStorer.
func (s *BaselineStore) MarkForcedReanchor(clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forced[clientID] = struct{}{}
	return nil
}

// HasForcedReanchor implements ForcedReanchorStorer.
func (s *BaselineStore) HasForcedReanchor(clientID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.forced[clientID]
	return ok, nil
}

// TakeForcedReanchor implements ForcedReanchorStorer.
func (s *BaselineStore) TakeForcedReanchor(clientID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.forced[clientID]
	delete(s.forced, clientID)
	return ok, nil
}

// SetClientTenant implements TenantStorer.
func (s *BaselineStore) SetClientTenant(clientID, tenant string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.baselines[clientID]; !ok {
		return fmt.Errorf("no baseline row for client %q", clientID)
	}
	s.tenants[clientID] = tenant
	return nil
}

// ClientTenant implements TenantStorer.
func (s *BaselineStore) ClientTenant(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tenant, ok := s.tenants[clientID]; ok && tenant != "" {
		return tenant, nil
	}
	return DefaultTenant, nil
}

// ListClients returns the clients with a PCR14 baseline.
func (s *BaselineStore) ListClients() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]string, 0, len(s.baselines))
	for id := range s.baselines {
		clients = append(clients, id)
	}
	return clients
}

// BaselineStats counts the clients and dates their first baselines.
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

// FormatPCR14 returns pcr14 in hex.
func FormatPCR14(pcr14 [types.HashSize]byte) string {
	return hex.EncodeToString(pcr14[:])
}

// CheckAndUpdateAgentHash implements AgentHashStorer.
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

	// a row with no agent hash is an out-of-band PCR14 pin and mismatches
	if existing.AgentHash != agentHash {
		out := *existing
		return TOFUMismatch, &out
	}

	existing.LastSeen = now
	existing.AttestCount++
	out := *existing
	return TOFUMatch, &out
}

// CheckAndUpdateBootPCRs implements BootBaselineStorer.
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

// CheckAndUpdateAttestation implements AtomicBaselineStorer under the store
// mutex.
func (s *BaselineStore) CheckAndUpdateAttestation(clientID string,
	pcr14, agentHash [types.HashSize]byte,
	boot *BootBaseline, consent bool,
) AttestationOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	outcome := AttestationOutcome{BootProvided: boot != nil, PCR14Result: TOFUError}
	spent := func() bool {
		if _, ok := s.forced[clientID]; !ok {
			outcome.AgentHashResult = TOFUError
			outcome.PCR14Result = TOFUError
			outcome.BootResult = TOFUError
			return false
		}
		delete(s.forced, clientID)
		return true
	}

	existing, exists := s.baselines[clientID]
	if !exists {
		if boot != nil && consent && !spent() {
			return outcome
		}
		b := &ClientBaseline{
			PCR14:       pcr14,
			AgentHash:   agentHash,
			FirstSeen:   now,
			LastSeen:    now,
			AttestCount: 1,
		}
		snap := *b
		outcome.AgentHashResult = TOFUFirstUse
		outcome.AgentHashBaseline = &snap
		outcome.PCR14Result = TOFUFirstUse

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
		snap := *existing
		outcome.AgentHashResult = TOFUMismatch
		outcome.AgentHashBaseline = &snap
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	default:
		outcome.AgentHashResult = TOFUMatch
	}

	// every road that creates a row writes PCR14 with it
	if existing.PCR14 != pcr14 {
		snap := *existing
		outcome.PCR14Result = TOFUMismatch
		outcome.AgentHashBaseline = &snap
		if boot != nil {
			outcome.BootResult = TOFUError
		}
		return outcome
	}
	outcome.PCR14Result = TOFUMatch

	if boot != nil {
		existingBoot, hasBoot := s.bootBaselines[clientID]
		if !hasBoot {
			if consent && !spent() {
				return outcome
			}
			outcome.BootResult = TOFUFirstUse
		} else if existingBoot.PCR0 != boot.PCR0 ||
			existingBoot.PCR1 != boot.PCR1 ||
			existingBoot.PCR7 != boot.PCR7 {
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

// RecordKernelHash implements KernelHashRecorder.
func (s *BaselineStore) RecordKernelHash(clientID string,
	kernelHash [types.HashSize]byte,
) (prev [types.HashSize]byte, had bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, known := s.baselines[clientID]; !known {
		return prev, false, nil
	}

	prev, had = s.kernelHashes[clientID]
	s.kernelHashes[clientID] = kernelHash
	return prev, had, nil
}

// RecordMachineKeys implements MachineKeysRecorder.
func (s *BaselineStore) RecordMachineKeys(clientID string, keys []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, known := s.baselines[clientID]; !known {
		return nil, nil
	}

	prev := s.machineKeys[clientID]
	s.machineKeys[clientID] = keys
	return prev, nil
}

// GetMachineKeys implements MachineKeysRecorder.
func (s *BaselineStore) GetMachineKeys(clientID string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.machineKeys[clientID]
}
