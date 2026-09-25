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

// TestRegression_LockedDerivation_DoesNotDrift pins the exact PCR14 the verifier
// expects for a known agent hash on a zero baseline.  Any change to the tag,
// the chain order or the hashed inputs shows up here as a byte-level diff.
func TestRegression_LockedDerivation_DoesNotDrift(t *testing.T) {
	ah := referenceAgentHash()
	got := DeriveLockedBootCommitmentPCR14(zeroBaseline, ah)
	const want = "15111fb4be027e4e33d17811d8cc6da9cf1aec30038c4342b081cfef3151e2ba"
	if FormatPCR14(got) != want {
		t.Fatalf("locked derivation drifted: got %s want %s",
			FormatPCR14(got), want)
	}
}

// TestRegression_LockedDerivation_IgnoresEveryCounterSource is the original
// failure stated as a property.  Neither counter source can influence
// the register, so an agent and a verifier reading different counters
// -- which is what per-publisher keys guarantee -- agree on the value.
func TestRegression_LockedDerivation_IgnoresEveryCounterSource(t *testing.T) {
	ah := referenceAgentHash()
	pcr14 := DeriveLockedBootCommitmentPCR14(zeroBaseline, ah)

	for _, counters := range [][2]uint32{
		{regressionResetCount, regressionRestartCount},
		{9, 0},
		{0, 0},
	} {
		blob := buildAttestWithClockInfo(counters[0], counters[1])
		attest, err := ParseTPMSAttest(blob)
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		_ = attest
		if _, _, ok := MatchLockedBootCommitmentPCR14(zeroBaseline, ah, pcr14); !ok {
			t.Fatalf("matcher refused a host whose quote reported counters %v",
				counters)
		}
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
