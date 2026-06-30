// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Fuzz Tests

package verify

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// fuzzes the TPMS_ATTEST parser
func FuzzParseTPMSAttest(f *testing.F) {
	f.Add(realTPMSAttestBlob)

	f.Fuzz(func(t *testing.T, data []byte) {
		attest, err := ParseTPMSAttest(data)
		if err != nil {
			if attest != nil {
				t.Error("ParseTPMSAttest returned non-nil attest with error")
			}
			return
		}

		if attest == nil {
			t.Error("ParseTPMSAttest returned nil without error")
		}
	})
}

// fuzzes the PCR digest verification logic
func FuzzVerifyPCRDigest(f *testing.F) {
	pcrMask := uint32((1 << 0) | (1 << 1) | (1 << 14))
	var pcrValues [types.PCRCount][types.HashSize]byte
	for i := range types.HashSize {
		pcrValues[0][i] = byte(i)
		pcrValues[1][i] = byte(i + 0x20)
		pcrValues[14][i] = byte(i + 0x40)
	}

	h := sha256.New()
	h.Write(pcrValues[0][:])
	h.Write(pcrValues[1][:])
	h.Write(pcrValues[14][:])
	digest := h.Sum(nil)

	validBlob := buildTestAttestBlob(digest)

	f.Add(validBlob, []byte("valid args"))

	f.Fuzz(func(t *testing.T, attestData []byte, _ []byte) {
		err := VerifyPCRDigest(attestData, &pcrValues, pcrMask)

		parsed, parseErr := ParseTPMSAttest(attestData)
		if parseErr != nil {
			if err == nil {
				t.Fatal("VerifyPCRDigest accepted an attest blob the parser rejects")
			}
			return
		}

		// independently derive whether the digest should be accepted from
		// the parsed quote's own fields, then require VerifyPCRDigest to
		// reach the same verdict.
		// this catches a digest comparison or quote-precondition (type/alg/empty)
		// check that wrongly accepts or rejects, which the no-oracle version could
		// never see
		want := parsed.Type == TPMSTAttestQuote &&
			parsed.QuoteInfo != nil &&
			len(parsed.QuoteInfo.PCRDigest) != 0 &&
			parsed.QuoteInfo.PCRHashAlg == types.TPMAlgSHA256
		if want {
			h := sha256.New()
			for i := range types.PCRCount {
				if pcrMask&(uint32(1)<<i) != 0 {
					h.Write(pcrValues[i][:])
				}
			}
			want = bytes.Equal(h.Sum(nil), parsed.QuoteInfo.PCRDigest)
		}
		if want != (err == nil) {
			t.Fatalf("VerifyPCRDigest verdict %v disagrees with independent check %v", err == nil, want)
		}
	})
}
