// SPDX-License-Identifier: MIT
// LOTA Verifier - PCR14 boot-commitment derivation and TOFU tests

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// referenceBootCommitmentPCR14 reproduces the PCR14 derivation by hand
// so any drift between the helper and the wire spec gets caught.
func referenceBootCommitmentPCR14(agentHash [types.HashSize]byte, reset, restart uint32) [types.HashSize]byte {
	const tag = "LOTA-PCR14-BOOT-COMMITMENT-v1"
	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], reset)
	binary.BigEndian.PutUint32(counters[4:8], restart)

	commit := sha256.New()
	commit.Write([]byte(tag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	d := commit.Sum(nil)

	var zero [types.HashSize]byte
	final := sha256.New()
	final.Write(zero[:])
	final.Write(d)
	var out [types.HashSize]byte
	copy(out[:], final.Sum(nil))
	return out
}

func TestDeriveBootCommitmentPCR14_StableForSameInputs(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = byte(i)
	}

	a := DeriveBootCommitmentPCR14(agentHash, 5, 1)
	b := DeriveBootCommitmentPCR14(agentHash, 5, 1)
	if a != b {
		t.Fatal("derivation must be deterministic")
	}

	want := referenceBootCommitmentPCR14(agentHash, 5, 1)
	if a != want {
		t.Fatalf("derivation diverged from reference: got %x want %x", a, want)
	}
}

func TestDeriveBootCommitmentPCR14_ResetCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x42
	}

	old := DeriveBootCommitmentPCR14(agentHash, 7, 0)
	rebooted := DeriveBootCommitmentPCR14(agentHash, 8, 0)
	if old == rebooted {
		t.Fatal("PCR14 must change when resetCount advances")
	}
}

func TestDeriveBootCommitmentPCR14_RestartCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0xAB
	}

	a := DeriveBootCommitmentPCR14(agentHash, 7, 0)
	b := DeriveBootCommitmentPCR14(agentHash, 7, 1)
	if a == b {
		t.Fatal("PCR14 must change when restartCount advances")
	}
}

func TestAgentHashStore_MemoryFirstUseAndMatch(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x11
	}
	for i := range agentHash {
		agentHash[i] = 0x22
	}

	res, b := bs.CheckAndUpdateAgentHash("client-1", pcr14, agentHash)
	if res != TOFUFirstUse {
		t.Fatalf("expected TOFUFirstUse, got %v", res)
	}
	if b.AgentHash != agentHash {
		t.Fatalf("snapshot must hold pinned agent_hash, got %x", b.AgentHash)
	}

	res, _ = bs.CheckAndUpdateAgentHash("client-1", pcr14, agentHash)
	if res != TOFUMatch {
		t.Fatalf("expected TOFUMatch, got %v", res)
	}

	var tampered [types.HashSize]byte
	tampered[0] = 0xFF
	res, snap := bs.CheckAndUpdateAgentHash("client-1", pcr14, tampered)
	if res != TOFUMismatch {
		t.Fatalf("expected TOFUMismatch on agent_hash drift, got %v", res)
	}
	if snap.AgentHash != agentHash {
		t.Fatalf("mismatch snapshot must expose stored value, got %x", snap.AgentHash)
	}
}

func TestAgentHashStore_MemoryBackfillsLegacyRow(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x33
	}
	for i := range agentHash {
		agentHash[i] = 0x44
	}

	// simulate a legacy row created by CheckAndUpdate() with no AgentHash
	bs.CheckAndUpdate("legacy", pcr14)

	res, snap := bs.CheckAndUpdateAgentHash("legacy", pcr14, agentHash)
	if res != TOFULegacyBackfill {
		t.Fatalf("legacy row must report TOFULegacyBackfill on first agent_hash, got %v", res)
	}
	if snap.AgentHash != agentHash {
		t.Fatalf("backfilled agent_hash mismatch: got %x", snap.AgentHash)
	}

	// subsequent rounds must take the regular match branch, not another
	// backfill, so the audit signal fires exactly once per client.
	res2, _ := bs.CheckAndUpdateAgentHash("legacy", pcr14, agentHash)
	if res2 != TOFUMatch {
		t.Fatalf("second round must return TOFUMatch, got %v", res2)
	}
}

// TestMemoryAtomicAttestation_FirstUseSeedsBothHalves asserts that
// CheckAndUpdateAttestation on a fresh client commits the agent_hash
// pin and the boot baseline in a single critical section: a subsequent
// call with a different boot baseline must report TOFUMismatch from
// the canonical pin established by the first call.
func TestMemoryAtomicAttestation_FirstUseSeedsBothHalves(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x14
	}
	for i := range agentHash {
		agentHash[i] = 0x44
	}
	boot := &BootBaseline{}
	for i := range boot.PCR0 {
		boot.PCR0[i] = 0xB0
		boot.PCR1[i] = 0xB1
		boot.PCR7[i] = 0xB7
	}

	out := bs.CheckAndUpdateAttestation("atomic-c1", pcr14, agentHash, boot)
	if out.AgentHashResult != TOFUFirstUse {
		t.Fatalf("agent_hash first-use: got %v, want TOFUFirstUse", out.AgentHashResult)
	}
	if !out.BootProvided {
		t.Fatal("BootProvided must mirror non-nil boot input")
	}
	if out.BootResult != TOFUFirstUse {
		t.Fatalf("boot first-use: got %v, want TOFUFirstUse", out.BootResult)
	}

	rogue := &BootBaseline{}
	for i := range rogue.PCR0 {
		rogue.PCR0[i] = 0xAA
		rogue.PCR1[i] = 0xBB
		rogue.PCR7[i] = 0xCC
	}
	out2 := bs.CheckAndUpdateAttestation("atomic-c1", pcr14, agentHash, rogue)
	if out2.AgentHashResult != TOFUMatch {
		t.Fatalf("second-round agent_hash: got %v, want TOFUMatch", out2.AgentHashResult)
	}
	if out2.BootResult != TOFUMismatch {
		t.Fatalf("second-round boot with rogue pins: got %v, want TOFUMismatch", out2.BootResult)
	}
}

// TestMemoryAtomicAttestation_BootMismatchPreservesAgentHashRow asserts
// that a boot mismatch terminates the transaction without writing to
// the agent_hash side either: a subsequent good attestation must still
// see the original (non-incremented) attest_count.
func TestMemoryAtomicAttestation_BootMismatchPreservesAgentHashRow(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x21
	}
	for i := range agentHash {
		agentHash[i] = 0x42
	}
	good := &BootBaseline{}
	for i := range good.PCR0 {
		good.PCR0[i] = 0x01
		good.PCR1[i] = 0x02
		good.PCR7[i] = 0x07
	}
	rogue := &BootBaseline{}
	for i := range rogue.PCR0 {
		rogue.PCR0[i] = 0x99
	}

	first := bs.CheckAndUpdateAttestation("atomic-c2", pcr14, agentHash, good)
	if first.AgentHashResult != TOFUFirstUse || first.BootResult != TOFUFirstUse {
		t.Fatalf("seed call: agent=%v boot=%v",
			first.AgentHashResult, first.BootResult)
	}
	if first.AgentHashBaseline.AttestCount != 1 {
		t.Fatalf("seed attest_count: got %d, want 1",
			first.AgentHashBaseline.AttestCount)
	}

	bad := bs.CheckAndUpdateAttestation("atomic-c2", pcr14, agentHash, rogue)
	if bad.BootResult != TOFUMismatch {
		t.Fatalf("rogue boot must mismatch, got %v", bad.BootResult)
	}

	// re-attest with good pins; attest_count must still increment from
	// 1 (the seed write) to 2, proving the mismatch did not bump the
	// counter behind the operator's back.
	good2 := bs.CheckAndUpdateAttestation("atomic-c2", pcr14, agentHash, good)
	if good2.AgentHashResult != TOFUMatch || good2.BootResult != TOFUMatch {
		t.Fatalf("recovery call: agent=%v boot=%v",
			good2.AgentHashResult, good2.BootResult)
	}
	if good2.AgentHashBaseline.AttestCount != 2 {
		t.Fatalf("attest_count after recovery: got %d, want 2",
			good2.AgentHashBaseline.AttestCount)
	}
}

// TestMatchBootCommitmentPCR14_ExactMatch verifies that an attestation
// where the quote's restartCount equals the value the agent extended
// with is accepted with zero drift.
func TestMatchBootCommitmentPCR14_ExactMatch(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x5A
	}

	const resetCount, restartCount uint32 = 3, 7
	target := DeriveBootCommitmentPCR14(agentHash, resetCount, restartCount)

	expected, drift, ok := MatchBootCommitmentPCR14(agentHash,
		resetCount, restartCount, target, 1024)
	if !ok {
		t.Fatal("expected exact-match acceptance")
	}
	if drift != 0 {
		t.Fatalf("exact match must report zero drift, got %d", drift)
	}
	if expected != target {
		t.Fatal("matched expected value diverged from target")
	}
}

// TestMatchBootCommitmentPCR14_AcceptsRestartDriftWithinWindow models the
// laptop suspend/resume case: the agent extended PCR14 at restartCount
// = boot, then several TPM2_Startup(STATE) cycles later the quote
// reports a larger restartCount. The verifier must still match.
func TestMatchBootCommitmentPCR14_AcceptsRestartDriftWithinWindow(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0xC3
	}

	const (
		resetCount        uint32 = 4
		bootRestartCount  uint32 = 10
		quoteRestartCount uint32 = 14 // four suspend/resume cycles since boot
		maxSkew           uint32 = 1024
	)
	target := DeriveBootCommitmentPCR14(agentHash, resetCount, bootRestartCount)

	expected, drift, ok := MatchBootCommitmentPCR14(agentHash,
		resetCount, quoteRestartCount, target, maxSkew)
	if !ok {
		t.Fatal("expected acceptance within skew window")
	}
	if drift != quoteRestartCount-bootRestartCount {
		t.Fatalf("drift: got %d, want %d", drift, quoteRestartCount-bootRestartCount)
	}
	if expected != target {
		t.Fatal("matched expected value diverged from target")
	}
}

// TestMatchBootCommitmentPCR14_RejectsBeyondSkewWindow covers the upper
// bound: when the actual restart_count delta exceeds maxRestartSkew, the
// scan must give up and report no match.
func TestMatchBootCommitmentPCR14_RejectsBeyondSkewWindow(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x77
	}

	const (
		resetCount        uint32 = 1
		bootRestartCount  uint32 = 100
		quoteRestartCount uint32 = 200
		maxSkew           uint32 = 50 // delta of 100 > 50
	)
	target := DeriveBootCommitmentPCR14(agentHash, resetCount, bootRestartCount)

	expected, drift, ok := MatchBootCommitmentPCR14(agentHash,
		resetCount, quoteRestartCount, target, maxSkew)
	if ok {
		t.Fatal("expected rejection: drift exceeds maxRestartSkew")
	}
	if drift != 0 {
		t.Fatalf("rejection must report zero drift, got %d", drift)
	}
	if expected != DeriveBootCommitmentPCR14(agentHash, resetCount, quoteRestartCount) {
		t.Fatal("on no match, expected must be the exact quote derivation for logging")
	}
}

// TestMatchBootCommitmentPCR14_DoesNotIterateResetCount asserts that a
// resetCount mismatch is never accepted regardless of skew. resetCount
// only advances at TPM_INIT (cold boot), which kills the agent process
// and triggers a fresh extend; tolerating any resetCount drift would
// reopen the dirty-shutdown bypass that the boot-commitment design
// closed.
func TestMatchBootCommitmentPCR14_DoesNotIterateResetCount(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x99
	}

	// agent extended at resetCount=5; quote reports resetCount=6 (cold boot
	// happened, agent should have re-extended but, for the sake of the
	// test, has not).
	target := DeriveBootCommitmentPCR14(agentHash, 5, 0)

	_, drift, ok := MatchBootCommitmentPCR14(agentHash,
		6, 0, target, 1024)
	if ok {
		t.Fatal("expected rejection on resetCount mismatch")
	}
	if drift != 0 {
		t.Fatalf("rejection must report zero drift, got %d", drift)
	}
}

// TestMatchBootCommitmentPCR14_SkewBoundedByQuoteRestart covers the
// underflow guard: the scan must not wrap around uint32 when
// quoteRestartCount is smaller than maxRestartSkew.
func TestMatchBootCommitmentPCR14_SkewBoundedByQuoteRestart(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0xEE
	}

	const (
		resetCount        uint32 = 2
		quoteRestartCount uint32 = 3
		maxSkew           uint32 = 1024
	)
	// craft a target derived from restartCount=0 (within bounds of [0,3]).
	target := DeriveBootCommitmentPCR14(agentHash, resetCount, 0)

	_, drift, ok := MatchBootCommitmentPCR14(agentHash,
		resetCount, quoteRestartCount, target, maxSkew)
	if !ok {
		t.Fatal("expected acceptance: target is reachable within [0, quoteRestartCount]")
	}
	if drift != quoteRestartCount {
		t.Fatalf("drift: got %d, want %d", drift, quoteRestartCount)
	}
}

// TestMatchBootCommitmentPCR14_ZeroSkewIsExactOnly verifies that
// MaxRestartCountSkew=0 disables the scan entirely and only the exact
// quote derivation is accepted.
func TestMatchBootCommitmentPCR14_ZeroSkewIsExactOnly(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x01
	}

	target := DeriveBootCommitmentPCR14(agentHash, 1, 5)

	_, _, okExact := MatchBootCommitmentPCR14(agentHash, 1, 5, target, 0)
	if !okExact {
		t.Fatal("exact match must succeed even with zero skew")
	}

	_, _, okDrift := MatchBootCommitmentPCR14(agentHash, 1, 6, target, 0)
	if okDrift {
		t.Fatal("any drift must be rejected when maxRestartSkew=0")
	}
}
