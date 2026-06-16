// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - regression tests for the signed-clockinfo PCR14 fix
//
// Background. Production attestation on swtpm (Fedora 44, TPM 2.0
// simulator) failed with FAIL_INTEGRITY_MISMATCH after a clean install
// and successful enrollment. The agent had extended PCR14 with
// resetCount=9, restartCount=0 (values returned by Esys_ReadClock)
// while the TPM2_Quote signed a TPMS_ATTEST whose clockInfo carried
// resetCount=1973039075, restartCount=2947164106. The verifier
// rederived the expected PCR14 from the quote-carried counters and
// reported a mismatch because no agent_hash + counter combination it
// scanned reproduced the actual PCR14.
//
// The fix (commit "agent: bind PCR14 to AIK-signed clockInfo") makes
// the agent capture counters through an AIK-signed TPM2_Quote with an
// empty PCR selection so the value extended into PCR14 matches the
// clockInfo of the later attestation quote. The verifier side is
// unchanged: it parses TPMS_ATTEST.clockInfo and runs
// MatchLockedBootCommitmentPCR14 against the agent_hash baseline.
//
// These tests pin the contract on the verifier side so any future
// regression that changes the derivation, the counter parsing, or the
// matching logic surfaces immediately.

package verify

import (
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

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

// TestRegression_LockedDerivation_SwtpmCounters pins the exact PCR14
// the verifier expects when the agent extended with the swtpm-observed
// (signed) clockInfo counters. The expected_pcr14 emitted by the
// verifier in the failing log run was
// 69b35748b79e3bc3d3db72cc90364750c258d9da36c022ae729107dde3df7e4d -
// the post-fix derivation must reproduce that value byte for byte.
func TestRegression_LockedDerivation_SwtpmCounters(t *testing.T) {
	ah := referenceAgentHash()
	got := DeriveLockedBootCommitmentPCR14(ah, regressionResetCount,
		regressionRestartCount)
	const want = "69b35748b79e3bc3d3db72cc90364750c258d9da36c022ae729107dde3df7e4d"
	if FormatPCR14(got) != want {
		t.Fatalf("locked derivation drifted: got %s want %s",
			FormatPCR14(got), want)
	}
}

// TestRegression_LockedDerivation_ReadClockCountersDiverge confirms
// that the two counter sources (Esys_ReadClock vs Quote.clockInfo)
// produce different PCR14 derivations. This is the failure mode the
// fix removes: if the agent extended with ReadClock counters but the
// quote carried Quote counters, the verifier could never match.
func TestRegression_LockedDerivation_ReadClockCountersDiverge(t *testing.T) {
	ah := referenceAgentHash()
	signed := DeriveLockedBootCommitmentPCR14(ah, regressionResetCount,
		regressionRestartCount)
	// the helper reported resetCount=9, restartCount=0 in the failing
	// run; using those values would yield a different PCR14 (and did,
	// 938aae...).
	readclock := DeriveLockedBootCommitmentPCR14(ah, 9, 0)
	if signed == readclock {
		t.Fatal("PCR14 derivation collapsed to a counter-free value")
	}
	const wantReadClock = "938aaeb5093dedd13ae61e92cc309b0f5cba7de35879a14aeef8a778284d89dc"
	if FormatPCR14(readclock) != wantReadClock {
		t.Fatalf("ReadClock-style derivation drifted: got %s want %s",
			FormatPCR14(readclock), wantReadClock)
	}
}

// TestRegression_MatchLockedBootCommitment_AcceptsSignedQuote walks
// the verifier's accept path end-to-end against a TPMS_ATTEST built
// with the swtpm counters. After the fix the agent extends PCR14 with
// the same counters the quote carries, so the matcher returns matched
// = true on the exact derivation (no skew burn).
func TestRegression_MatchLockedBootCommitment_AcceptsSignedQuote(t *testing.T) {
	ah := referenceAgentHash()
	pcr14 := DeriveLockedBootCommitmentPCR14(ah, regressionResetCount,
		regressionRestartCount)

	exp, drift, ok := MatchLockedBootCommitmentPCR14(ah,
		regressionResetCount, regressionRestartCount, pcr14, 1024)
	if !ok {
		t.Fatalf("matcher rejected the signed-quote derivation; "+
			"expected accept, got expected=%s", FormatPCR14(exp))
	}
	if drift != 0 {
		t.Fatalf("matcher burned %d restart skew on exact derivation",
			drift)
	}
}

// TestRegression_MatchLockedBootCommitment_RejectsCounterDrift mirrors
// the pre-fix failure: the agent extended PCR14 with ReadClock counters
// (9, 0) but the verifier sees Quote.clockInfo (swtpm counters). The
// matcher must refuse the report. Confirms the skew window does not
// silently absorb the bug.
func TestRegression_MatchLockedBootCommitment_RejectsCounterDrift(t *testing.T) {
	ah := referenceAgentHash()
	pcr14ExtendedWithReadClock := DeriveLockedBootCommitmentPCR14(ah, 9, 0)

	_, _, ok := MatchLockedBootCommitmentPCR14(ah, regressionResetCount,
		regressionRestartCount, pcr14ExtendedWithReadClock, 1024)
	if ok {
		t.Fatal("matcher accepted a PCR14 extended with the wrong " +
			"counters; the swtpm regression would resurface silently")
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
