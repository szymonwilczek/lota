// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - PCR14 boot-commitment derivation and TOFU tests

package verify

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// zeroBaseline is the PCR14 content of a host whose firmware measured
// nothing into the register before the initramfs lock ran.
var zeroBaseline [types.HashSize]byte

func referenceInitramfsLockPCR14(reset, restart uint32) [types.HashSize]byte {
	const tag = "LOTA-PCR14-INITRAMFS-LOCK-v1"
	_, _ = reset, restart

	commit := sha256.New()
	commit.Write([]byte(tag))
	d := commit.Sum(nil)

	var zero [types.HashSize]byte
	final := sha256.New()
	final.Write(zero[:])
	final.Write(d)
	var out [types.HashSize]byte
	copy(out[:], final.Sum(nil))
	return out
}

func referenceLockedBootCommitmentPCR14(agentHash [types.HashSize]byte, reset, restart uint32) [types.HashSize]byte {
	const tag = "LOTA-PCR14-BOOT-COMMITMENT-v1"
	lockValue := referenceInitramfsLockPCR14(reset, restart)

	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], reset)
	binary.BigEndian.PutUint32(counters[4:8], restart)

	commit := sha256.New()
	commit.Write([]byte(tag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	d := commit.Sum(nil)

	final := sha256.New()
	final.Write(lockValue[:])
	final.Write(d)
	var out [types.HashSize]byte
	copy(out[:], final.Sum(nil))
	return out
}

func TestDeriveInitramfsLockPCR14_StableForSameInputs(t *testing.T) {
	a := DeriveInitramfsLockPCR14(zeroBaseline, 9, 2)
	b := DeriveInitramfsLockPCR14(zeroBaseline, 9, 2)
	if a != b {
		t.Fatal("initramfs lock derivation must be deterministic")
	}

	want := referenceInitramfsLockPCR14(9, 2)
	if a != want {
		t.Fatalf("initramfs lock derivation diverged from reference: got %x want %x", a, want)
	}

	drifted := DeriveInitramfsLockPCR14(zeroBaseline, 0xFFFFFFFF, 0xAABBCCDD)
	if drifted != a {
		t.Fatal("initramfs lock derivation must not depend on TPM clock counters")
	}
}

func TestDeriveLockedBootCommitmentPCR14_ChainsLockBeforeAgentCommit(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = byte(0x80 + i)
	}

	got := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 6, 3)
	want := referenceLockedBootCommitmentPCR14(agentHash, 6, 3)
	if got != want {
		t.Fatalf("locked derivation diverged from reference: got %x want %x", got, want)
	}

	if got != DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 6, 3) {
		t.Fatal("derivation must be deterministic")
	}
	if got == DeriveInitramfsLockPCR14(zeroBaseline, 6, 3) {
		t.Fatal("locked two-hop derivation must not collapse to the lock value")
	}
}

func TestDeriveLockedBootCommitmentPCR14_ResetCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x42
	}

	old := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 7, 0)
	rebooted := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 8, 0)
	if old == rebooted {
		t.Fatal("PCR14 must change when resetCount advances")
	}
}

func TestDeriveLockedBootCommitmentPCR14_RestartCountInvalidatesValue(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0xAB
	}

	a := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 7, 0)
	b := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 7, 1)
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

// TestAgentHashStore_MemoryRefusesUnpinnedRow covers a row that carries PCR14
// pin but no agent_hash.
// No attestation creates one -- every attestation writes the hash -- so it can
// only come from an out-of-band PCR14 pin, and the store refuses rather than
// adopting whichever hash arrives first.
func TestAgentHashStore_MemoryRefusesUnpinnedRow(t *testing.T) {
	bs := NewBaselineStore()

	var pcr14, agentHash [types.HashSize]byte
	for i := range pcr14 {
		pcr14[i] = 0x33
	}
	for i := range agentHash {
		agentHash[i] = 0x44
	}

	// row created by CheckAndUpdate() carries no AgentHash
	bs.CheckAndUpdate("unpinned", pcr14)

	res, snap := bs.CheckAndUpdateAgentHash("unpinned", pcr14, agentHash)
	if res != TOFUMismatch {
		t.Fatalf("row without a pinned agent_hash must mismatch, got %v", res)
	}
	var zero [types.HashSize]byte
	if snap.AgentHash != zero {
		t.Fatalf("refused round must not pin the incoming hash, got %x", snap.AgentHash)
	}

	// refusal is stable:
	// nothing was written, so retry mismatches again instead of finding
	// freshly adopted hash
	if res2, _ := bs.CheckAndUpdateAgentHash("unpinned", pcr14, agentHash); res2 != TOFUMismatch {
		t.Fatalf("second round must stay TOFUMismatch, got %v", res2)
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

// TestMatchLockedBootCommitmentPCR14_ExactMatch verifies that an attestation
// where the quote's restartCount equals the value the agent extended
// with is accepted with zero drift.
func TestMatchLockedBootCommitmentPCR14_ExactMatch(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x5A
	}

	const resetCount, restartCount uint32 = 3, 7
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount, restartCount)

	expected, drift, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash,
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

// TestMatchLockedBootCommitmentPCR14_AcceptsRestartDriftWithinWindow models the
// laptop suspend/resume case: the agent extended PCR14 at restartCount
// = boot, then several TPM2_Startup(STATE) cycles later the quote
// reports a larger restartCount. The verifier must still match.
func TestMatchLockedBootCommitmentPCR14_AcceptsRestartDriftWithinWindow(t *testing.T) {
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
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount, bootRestartCount)

	expected, drift, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash,
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

// TestMatchLockedBootCommitmentPCR14_RejectsBeyondSkewWindow covers the upper
// bound: when the actual restart_count delta exceeds maxRestartSkew, the
// scan must give up and report no match.
func TestMatchLockedBootCommitmentPCR14_RejectsBeyondSkewWindow(t *testing.T) {
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
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount, bootRestartCount)

	expected, drift, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash,
		resetCount, quoteRestartCount, target, maxSkew)
	if ok {
		t.Fatal("expected rejection: drift exceeds maxRestartSkew")
	}
	if drift != 0 {
		t.Fatalf("rejection must report zero drift, got %d", drift)
	}
	if expected != DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount, quoteRestartCount) {
		t.Fatal("on no match, expected must be the exact quote derivation for logging")
	}
}

// TestMatchLockedBootCommitmentPCR14_DoesNotIterateResetCount asserts that a
// resetCount mismatch is never accepted regardless of skew. resetCount
// only advances at TPM_INIT (cold boot), which kills the agent process
// and triggers a fresh extend; tolerating any resetCount drift would
// reopen the dirty-shutdown bypass that the boot-commitment design
// closed.
func TestMatchLockedBootCommitmentPCR14_DoesNotIterateResetCount(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x99
	}

	// agent extended at resetCount=5; quote reports resetCount=6 (cold boot
	// happened, agent should have re-extended but, for the sake of the
	// test, has not).
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 5, 0)

	_, drift, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash,
		6, 0, target, 1024)
	if ok {
		t.Fatal("expected rejection on resetCount mismatch")
	}
	if drift != 0 {
		t.Fatalf("rejection must report zero drift, got %d", drift)
	}
}

// TestMatchLockedBootCommitmentPCR14_SkewBoundedByQuoteRestart covers the
// underflow guard: the scan must not wrap around uint32 when
// quoteRestartCount is smaller than maxRestartSkew.
func TestMatchLockedBootCommitmentPCR14_SkewBoundedByQuoteRestart(t *testing.T) {
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
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount, 0)

	_, drift, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash,
		resetCount, quoteRestartCount, target, maxSkew)
	if !ok {
		t.Fatal("expected acceptance: target is reachable within [0, quoteRestartCount]")
	}
	if drift != quoteRestartCount {
		t.Fatalf("drift: got %d, want %d", drift, quoteRestartCount)
	}
}

// TestMatchLockedBootCommitmentPCR14_ZeroSkewIsExactOnly verifies that
// MaxRestartCountSkew=0 disables the scan entirely and only the exact
// quote derivation is accepted.
func TestMatchLockedBootCommitmentPCR14_ZeroSkewIsExactOnly(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x01
	}

	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 1, 5)

	_, _, okExact := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, 1, 5, target, 0)
	if !okExact {
		t.Fatal("exact match must succeed even with zero skew")
	}

	_, _, okDrift := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, 1, 6, target, 0)
	if okDrift {
		t.Fatal("any drift must be rejected when maxRestartSkew=0")
	}
}

// TestDefaultConfig_MaxRestartCountSkewIs64 pins the default skew at 64
// so the brute-force surface of the PCR14 boot-commitment matcher does
// not silently grow back to the historical 1024 value. Operators that
// truly need a wider window can still set MaxRestartCountSkew
// explicitly via the --max-restart-count-skew flag; reverting the
// default is a security-relevant change that must come with a
// matching test edit.
func TestDefaultConfig_MaxRestartCountSkewIs64(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxRestartCountSkew != 64 {
		t.Fatalf("DefaultConfig.MaxRestartCountSkew drifted: got %d want 64",
			cfg.MaxRestartCountSkew)
	}
}

// TestMatchLockedBootCommitmentPCR14_RejectsBeyondDefaultSkewWindow walks
// the matcher with the default skew and a quote restartCount that
// drifts just past it; rejection is mandatory because the matcher
// must not iterate past the default budget on production reports.
func TestMatchLockedBootCommitmentPCR14_RejectsBeyondDefaultSkewWindow(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x7E
	}

	const (
		resetCount        uint32 = 4
		bootRestartCount  uint32 = 1
		defaultSkew              = uint32(64)
		quoteRestartCount        = bootRestartCount + defaultSkew + 1
	)
	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount,
		bootRestartCount)

	_, _, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, resetCount,
		quoteRestartCount, target, defaultSkew)
	if ok {
		t.Fatal("matcher accepted a drift past the default skew window")
	}
}

// proves both derivations anchor on the supplied baseline
// (the firmware/shim MOK PCR14 content on UEFI Secure Boot) instead of hardcoded 0^32,
// and that the matcher binds it
func TestDerivePCR14_BaselineAware(t *testing.T) {
	var agentHash, shim [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x42
		shim[i] = 0xAB
	}

	if DeriveInitramfsLockPCR14(zeroBaseline, 1, 0) == DeriveInitramfsLockPCR14(shim, 1, 0) {
		t.Fatal("initramfs-lock PCR14 must depend on the baseline")
	}
	if DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 1, 0) == DeriveLockedBootCommitmentPCR14(shim, agentHash, 1, 0) {
		t.Fatal("locked boot-commitment PCR14 must depend on the baseline")
	}

	// two-hop locked derivation must chain the baseline-aware lock value
	// SHA256(baseline||lockCommit) before the boot commit
	lock := DeriveInitramfsLockPCR14(shim, 6, 3)
	var counters [8]byte
	binary.BigEndian.PutUint32(counters[0:4], 6)
	binary.BigEndian.PutUint32(counters[4:8], 3)
	commit := sha256.New()
	commit.Write([]byte(bootCommitmentTag))
	commit.Write(agentHash[:])
	commit.Write(counters[:])
	pcr := sha256.New()
	pcr.Write(lock[:])
	pcr.Write(commit.Sum(nil))
	var want [types.HashSize]byte
	copy(want[:], pcr.Sum(nil))
	if DeriveLockedBootCommitmentPCR14(shim, agentHash, 6, 3) != want {
		t.Fatal("locked derivation must chain the baseline-aware lock value before the boot commit")
	}

	// matcher must accept a target derived with the same baseline
	// and reject one derived against the wrong (zero) baseline
	target := DeriveLockedBootCommitmentPCR14(shim, agentHash, 6, 3)
	if _, _, ok := MatchLockedBootCommitmentPCR14(shim, agentHash, 6, 3, target, 0); !ok {
		t.Fatal("matcher must accept a target derived with the same baseline")
	}
	if _, _, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, 6, 3, target, 0); ok {
		t.Fatal("matcher must reject a target derived against a different baseline")
	}
}

// proves the verifier reconstructs the pre-LOTA PCR14 baseline
// (shim/MOK on UEFI Secure Boot) by replaying the firmware event log, and that
// the reconstructed baseline feeds the boot-commitment derivation
func TestPCR14BaselineFromEventLog(t *testing.T) {
	// nil log -> zero baseline (UEFI host booting without shim, so nothing
	// ever extended PCR14 before LOTA)
	if PCR14BaselineFromEventLog(nil) != zeroBaseline {
		t.Fatal("nil event log must yield a zero baseline")
	}

	// two synthetic shim PCR14 measurements (MokList, MokListRT)
	d1 := sha256.Sum256([]byte("MokList"))
	d2 := sha256.Sum256([]byte("MokListRT"))
	parsed := &ParsedEventLog{
		AlgorithmList: []uint16{AlgSHA256},
		Entries: []EventLogEntry{
			{PCRIndex: 14, Digests: map[uint16][]byte{AlgSHA256: d1[:]}},
			{PCRIndex: 7, Digests: map[uint16][]byte{AlgSHA256: sha256Sum("unrelated")}},
			{PCRIndex: 14, Digests: map[uint16][]byte{AlgSHA256: d2[:]}},
		},
	}

	// expected B = extend(extend(0, d1), d2), ignoring the PCR7 event
	step := sha256.New()
	var acc [types.HashSize]byte
	step.Write(acc[:])
	step.Write(d1[:])
	copy(acc[:], step.Sum(nil))
	step.Reset()
	step.Write(acc[:])
	step.Write(d2[:])
	copy(acc[:], step.Sum(nil))

	got := PCR14BaselineFromEventLog(parsed)
	if got != acc {
		t.Fatalf("baseline mismatch: PCR14 replay did not fold only the PCR14 events\n got %x\nwant %x", got, acc)
	}
	if got == zeroBaseline {
		t.Fatal("a non-empty shim PCR14 log must produce a non-zero baseline")
	}

	// reconstructed baseline must change the locked derivation vs zero
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x42
	}
	if DeriveLockedBootCommitmentPCR14(got, agentHash, 3, 0) ==
		DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash, 3, 0) {
		t.Fatal("event-log baseline must feed the locked boot-commitment derivation")
	}
}

func sha256Sum(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}
