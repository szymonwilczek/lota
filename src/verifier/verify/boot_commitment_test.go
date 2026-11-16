// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

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

func referenceInitramfsLockPCR14() [types.HashSize]byte {
	const tag = "LOTA-PCR14-INITRAMFS-LOCK-v1"

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

func referenceLockedBootCommitmentPCR14(agentHash [types.HashSize]byte) [types.HashSize]byte {
	const tag = "LOTA-PCR14-BOOT-COMMITMENT-v1"
	lockValue := referenceInitramfsLockPCR14()

	commit := sha256.New()
	commit.Write([]byte(tag))
	commit.Write(agentHash[:])
	d := commit.Sum(nil)

	final := sha256.New()
	final.Write(lockValue[:])
	final.Write(d)
	var out [types.HashSize]byte
	copy(out[:], final.Sum(nil))
	return out
}

func TestDeriveInitramfsLockPCR14_StableForSameInputs(t *testing.T) {
	a := DeriveInitramfsLockPCR14(zeroBaseline)
	b := DeriveInitramfsLockPCR14(zeroBaseline)
	if a != b {
		t.Fatal("initramfs lock derivation must be deterministic")
	}

	want := referenceInitramfsLockPCR14()
	if a != want {
		t.Fatalf("initramfs lock derivation diverged from reference: got %x want %x", a, want)
	}
}

func TestDeriveLockedBootCommitmentPCR14_ChainsLockBeforeAgentCommit(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = byte(0x80 + i)
	}

	got := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash)
	want := referenceLockedBootCommitmentPCR14(agentHash)
	if got != want {
		t.Fatalf("locked derivation diverged from reference: got %x want %x", got, want)
	}

	if got != DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash) {
		t.Fatal("derivation must be deterministic")
	}
	if got == DeriveInitramfsLockPCR14(zeroBaseline) {
		t.Fatal("locked two-hop derivation must not collapse to the lock value")
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

	out := bs.CheckAndUpdateAttestation("atomic-c1", DefaultTenant, pcr14,
		agentHash, boot, false)
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
	out2 := bs.CheckAndUpdateAttestation("atomic-c1", DefaultTenant, pcr14,
		agentHash, rogue, false)
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

	first := bs.CheckAndUpdateAttestation("atomic-c2", DefaultTenant, pcr14,
		agentHash, good, false)
	if first.AgentHashResult != TOFUFirstUse || first.BootResult != TOFUFirstUse {
		t.Fatalf("seed call: agent=%v boot=%v",
			first.AgentHashResult, first.BootResult)
	}
	if first.AgentHashBaseline.AttestCount != 1 {
		t.Fatalf("seed attest_count: got %d, want 1",
			first.AgentHashBaseline.AttestCount)
	}

	bad := bs.CheckAndUpdateAttestation("atomic-c2", DefaultTenant, pcr14,
		agentHash, rogue, false)
	if bad.BootResult != TOFUMismatch {
		t.Fatalf("rogue boot must mismatch, got %v", bad.BootResult)
	}

	// re-attest with good pins; attest_count must still increment from
	// 1 (the seed write) to 2, proving the mismatch did not bump the
	// counter behind the operator's back.
	good2 := bs.CheckAndUpdateAttestation("atomic-c2", DefaultTenant, pcr14,
		agentHash, good, false)
	if good2.AgentHashResult != TOFUMatch || good2.BootResult != TOFUMatch {
		t.Fatalf("recovery call: agent=%v boot=%v",
			good2.AgentHashResult, good2.BootResult)
	}
	if good2.AgentHashBaseline.AttestCount != 2 {
		t.Fatalf("attest_count after recovery: got %d, want 2",
			good2.AgentHashBaseline.AttestCount)
	}
}

// TestMatchLockedBootCommitmentPCR14_ExactMatch verifies that the register
// a host presents is accepted when it is the one the reported agent hash derives.
func TestMatchLockedBootCommitmentPCR14_ExactMatch(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x5A
	}

	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash)

	expected, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, target)
	if !ok {
		t.Fatal("expected exact-match acceptance")
	}
	if expected != target {
		t.Fatal("matched expected value diverged from target")
	}
}

// TestMatchLockedBootCommitmentPCR14_RejectsForeignRegister keeps the binding
// honest now that no scan can absorb a difference: a register the reported
// agent hash does not derive is refused, and the expected value returned for
// the security log is that derivation.
func TestMatchLockedBootCommitmentPCR14_RejectsForeignRegister(t *testing.T) {
	var agentHash, otherHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x77
		otherHash[i] = 0x78
	}

	target := DeriveLockedBootCommitmentPCR14(zeroBaseline, otherHash)

	expected, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, target)
	if ok {
		t.Fatal("a register another binary committed was accepted")
	}
	if expected != DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash) {
		t.Fatal("on no match, expected must be the reported hash's derivation for logging")
	}
}

// TestMatchLockedBootCommitmentPCR14_RejectsForeignBaseline covers the other
// input: a host whose firmware measured a different PCR 14 baseline does not
// match a register derived over the zero baseline.
func TestMatchLockedBootCommitmentPCR14_RejectsForeignBaseline(t *testing.T) {
	var agentHash [types.HashSize]byte
	for i := range agentHash {
		agentHash[i] = 0x99
	}

	var shimBaseline [types.HashSize]byte
	shimBaseline[0] = 0x17

	target := DeriveLockedBootCommitmentPCR14(shimBaseline, agentHash)

	if _, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, target); ok {
		t.Fatal("a register anchored on another baseline was accepted")
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

	if DeriveInitramfsLockPCR14(zeroBaseline) == DeriveInitramfsLockPCR14(shim) {
		t.Fatal("initramfs-lock PCR14 must depend on the baseline")
	}
	if DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash) == DeriveLockedBootCommitmentPCR14(shim, agentHash) {
		t.Fatal("locked boot-commitment PCR14 must depend on the baseline")
	}

	// two-hop locked derivation must chain the baseline-aware lock value
	// SHA256(baseline||lockCommit) before the boot commit
	lock := DeriveInitramfsLockPCR14(shim)
	commit := sha256.New()
	commit.Write([]byte(bootCommitmentTag))
	commit.Write(agentHash[:])
	pcr := sha256.New()
	pcr.Write(lock[:])
	pcr.Write(commit.Sum(nil))
	var want [types.HashSize]byte
	copy(want[:], pcr.Sum(nil))
	if DeriveLockedBootCommitmentPCR14(shim, agentHash) != want {
		t.Fatal("locked derivation must chain the baseline-aware lock value before the boot commit")
	}

	// matcher must accept a target derived with the same baseline
	// and reject one derived against the wrong (zero) baseline
	target := DeriveLockedBootCommitmentPCR14(shim, agentHash)
	if _, ok := MatchLockedBootCommitmentPCR14(shim, agentHash, target); !ok {
		t.Fatal("matcher must accept a target derived with the same baseline")
	}
	if _, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, agentHash, target); ok {
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
	if DeriveLockedBootCommitmentPCR14(got, agentHash) ==
		DeriveLockedBootCommitmentPCR14(zeroBaseline, agentHash) {
		t.Fatal("event-log baseline must feed the locked boot-commitment derivation")
	}
}

func sha256Sum(s string) []byte {
	d := sha256.Sum256([]byte(s))
	return d[:]
}

// swtpm-observed counters from the failing attestation that motivated
// the fix. Hardcoded so any drift in the derivation produces a stable
// diff in the test output.
const (
	regressionResetCount   uint32 = 1973039075 // 0x75968AE3
	regressionRestartCount uint32 = 2947164106 // 0xAFAFCB8A
)

// referenceAgentHash mirrors the agent binary self-hash captured in
// the failing run (sha256(/usr/bin/lota-agent)). Keeping it as a
// fixed test input keeps the expected PCR14 stable across machines.
func referenceAgentHash() [types.HashSize]byte {
	const hex = "18a8bae816a01387ef2d3ac7d4e5e216f722e2b8fc5a7c5e64a3c75ded7eb0df"
	var out [types.HashSize]byte
	for i := 0; i < types.HashSize; i++ {
		hi := hexDigit(hex[i*2])
		lo := hexDigit(hex[i*2+1])
		out[i] = (hi << 4) | lo
	}
	return out
}

func hexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	panic("bad hex")
}

// TestRegression_LockedDerivation_DoesNotDrift pins the exact PCR14 the verifier
// expects for a known agent hash on a zero baseline.  Any change to the tag,
// the chain order or the hashed inputs shows up here as a byte-level diff.
func TestRegression_LockedDerivation_DoesNotDrift(t *testing.T) {
	ah := referenceAgentHash()
	got := DeriveLockedBootCommitmentPCR14(zeroBaseline, ah)
	const want = "64a2192a9accbbc60a153cd982373354188e3bdf97395b0395cf2c9cd3093173"
	if FormatPCR14(got) != want {
		t.Fatalf("locked derivation drifted: got %s want %s",
			FormatPCR14(got), want)
	}
}

// TestRegression_TPMSAttestParser_PreservesCounters cross-checks the
// verifier's binary-level parser against the same swtpm counters. The
// fix moved the agent-side capture to TPM2_Quote.clockInfo, so the
// verifier's TPMS_ATTEST.clockInfo extraction is now the single source
// of truth for the verifier-side derivation; any byte/endianness drift
// in ParseTPMSAttest would re-enable the original mismatch.
func TestRegression_TPMSAttestParser_PreservesCounters(t *testing.T) {
	blob := buildAttestWithClockInfo(regressionResetCount,
		regressionRestartCount)
	attest, err := ParseTPMSAttest(blob)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if attest.ClockInfo.ResetCount != regressionResetCount {
		t.Fatalf("ResetCount drifted: got %d want %d",
			attest.ClockInfo.ResetCount, regressionResetCount)
	}
	if attest.ClockInfo.RestartCount != regressionRestartCount {
		t.Fatalf("RestartCount drifted: got %d want %d",
			attest.ClockInfo.RestartCount, regressionRestartCount)
	}
}

// buildAttestWithClockInfo emits a TPMS_ATTEST_QUOTE byte blob carrying
// the supplied resetCount/restartCount inside clockInfo. The PCR
// digest is the zero hash so callers can ignore the quote payload.
func buildAttestWithClockInfo(reset, restart uint32) []byte {
	var buf []byte

	// magic
	buf = appendU32BE(buf, 0xff544347)
	// type: TPM_ST_ATTEST_QUOTE
	buf = appendU16BE(buf, 0x8018)
	// qualifiedSigner (empty)
	buf = appendU16BE(buf, 0)
	// extraData (32 bytes of arbitrary data)
	buf = appendU16BE(buf, 32)
	for i := 0; i < 32; i++ {
		buf = append(buf, byte(i^0x33))
	}
	// clockInfo: clock (8) || resetCount (4) || restartCount (4) || safe (1)
	buf = appendU64BE(buf, 0xDEADBEEFCAFEBABE)
	buf = appendU32BE(buf, reset)
	buf = appendU32BE(buf, restart)
	buf = append(buf, 1) // safe
	// firmwareVersion
	buf = appendU64BE(buf, 0x0123456789ABCDEF)
	// quoteInfo: TPML_PCR_SELECTION with one entry covering PCR14
	buf = appendU32BE(buf, 1)      // count
	buf = appendU16BE(buf, 0x000B) // SHA-256
	buf = append(buf, 3)           // sizeofSelect
	buf = append(buf, 0, 0x40, 0)  // PCR 14 selected
	// pcrDigest (zeroed, 32 bytes)
	buf = appendU16BE(buf, 32)
	for i := 0; i < 32; i++ {
		buf = append(buf, 0)
	}
	return buf
}

func appendU16BE(buf []byte, v uint16) []byte {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	return append(buf, tmp[:]...)
}

func appendU32BE(buf []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(buf, tmp[:]...)
}

func appendU64BE(buf []byte, v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)
	return append(buf, tmp[:]...)
}

// checkRefusedFirstUseKeepsTenant pins a client of tenant acme, refuses
// its next round on a moved boot PCR, and lists it under acme alone.
func checkRefusedFirstUseKeepsTenant(t *testing.T, s interface {
	AtomicBaselineStorer
	BaselineStorer
}) {
	t.Helper()
	var pcr14, agentHash [types.HashSize]byte
	pcr14[0], agentHash[0] = 0x14, 0x44
	boot := &BootBaseline{}
	boot.PCR0[0] = 0xB0
	moved := &BootBaseline{}
	moved.PCR0[0] = 0xAA

	out := s.CheckAndUpdateAttestation("tenant-c1", "acme", pcr14,
		agentHash, boot, false)
	if out.BootResult != TOFUFirstUse {
		t.Fatalf("first round: boot %v, want TOFUFirstUse",
			out.BootResult)
	}
	out = s.CheckAndUpdateAttestation("tenant-c1", "acme", pcr14,
		agentHash, moved, false)
	if out.BootResult != TOFUMismatch {
		t.Fatalf("moved boot PCR: boot %v, want TOFUMismatch",
			out.BootResult)
	}
	out = s.CheckAndUpdateAttestation("tenant-c2", "acme", pcr14,
		agentHash, nil, false)
	if out.PCR14Result != TOFUFirstUse {
		t.Fatalf("no boot: PCR 14 %v, want TOFUFirstUse",
			out.PCR14Result)
	}

	for _, tc := range []struct {
		tenant string
		want   int
	}{{"acme", 2}, {DefaultTenant, 0}} {
		got, err := s.ListClientsAfter([]string{tc.tenant}, "", 10)
		if err != nil {
			t.Fatalf("ListClientsAfter(%s): %v", tc.tenant, err)
		}
		if len(got) != tc.want {
			t.Errorf("ListClientsAfter(%s) = %v, want %d clients",
				tc.tenant, got, tc.want)
		}
	}
}

func TestMemoryAtomicAttestation_FirstUseKeepsTenant(t *testing.T) {
	checkRefusedFirstUseKeepsTenant(t, NewBaselineStore())
}
